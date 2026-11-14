"""B-041: the welcome / zero-file / platform-profile auto-trigger in ctf.fastlane.

`welcome_class` classifies the challenges intake auto-runs the fast lane on, and `try_welcome` is the
OFFLINE recovery: one unambiguous inline brief flag (deterministic, no network), else a flagless human
step. All inputs are SYNTHETIC; nothing here touches the wire or submits.

Run:  .venv/bin/python -m pytest tests/test_fastlane_welcome.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf import fastlane                    # noqa: E402

FLAG = "CSCTF{w3lc0me_ab0ard}"


def test_welcome_class_detects_welcome_rules_and_profile_and_declines_others():
    assert fastlane.welcome_class({"name": "Welcome Aboard", "category": "misc",
                                   "description": "Say hi!"}) == "welcome"
    assert fastlane.welcome_class({"name": "Read the Rules", "category": "sanity",
                                   "description": "prove you read them"}) == "sanity"
    assert fastlane.welcome_class({"name": "Where U From", "category": "misc",
                                   "description": "set your country in your team profile"}) == "platform-profile"
    # a normal challenge is not the fast lane's, even with an intro-sounding word nowhere in it
    assert fastlane.welcome_class({"name": "Heap Overflow", "category": "pwn",
                                   "description": "pop a shell on the service"}) is None


def test_welcome_class_detects_a_bare_sanity_category_with_no_rules_wording():
    # The `sanity` CATEGORY alone classifies, independent of any rules/welcome/profile wording: the
    # name and brief carry none of the word-list terms (no "sanity", no "the rules"), so only the
    # `cat == "sanity"` branch can fire. Kills the mutation that drops that branch.
    detail = {"name": "Checkpoint", "category": "sanity", "description": "confirm your setup works"}
    assert fastlane.welcome_class(detail) == "sanity"
    r = fastlane.try_welcome(detail, None, base_url="https://board.example.test")
    assert r is not None and r["klass"] == "sanity" and r["flag"] is None and r.get("instruction")


def test_welcome_class_ignores_loose_wording_in_the_description_prose():
    # B-041 finding 2: a non-welcome challenge whose BODY merely quotes "the rules" (or "your profile")
    # must NOT be classed welcome/sanity/profile -- otherwise a lone brief flag beside that prose would
    # be force-promoted to a confirmed solve. The class signal is the name/category only.
    rules = {"name": "Forensics Image", "category": "forensics",
             "description": f"Per the rules you must stay in scope. The capture hides {FLAG}."}
    assert fastlane.welcome_class(rules) is None
    assert fastlane.try_welcome(rules, None) is None
    profile = {"name": "Packet Hunt", "category": "forensics",
               "description": f"Check your profile of captured sessions; one holds {FLAG}."}
    assert fastlane.welcome_class(profile) is None
    assert fastlane.try_welcome(profile, None) is None


def test_try_welcome_records_the_zero_file_flag(tmp_path):
    # B-041 finding 3: files_dir is a real discriminator -- the result records whether the welcome
    # challenge ships handout files (the item's zero-file angle), both on the inline-flag path and the
    # human-step path.
    detail = {"name": "Welcome!", "category": "misc",
              "description": f"Welcome aboard. Freebie: {FLAG}."}
    assert fastlane.try_welcome(detail, None)["zero_file"] is True
    empty = tmp_path / "empty"
    empty.mkdir()
    assert fastlane.try_welcome(detail, empty)["zero_file"] is True
    withfile = tmp_path / "withfile"
    (withfile / "sub").mkdir(parents=True)
    (withfile / "sub" / "handout.bin").write_bytes(b"\x00\x01")
    r = fastlane.try_welcome(detail, withfile)
    assert r["zero_file"] is False and r["flag"] == FLAG     # flag still recovered; just not zero-file
    # a profile challenge with no inline flag also carries zero_file
    prof = {"name": "Where U From", "category": "misc", "description": "set your country in the profile"}
    assert fastlane.try_welcome(prof, None)["zero_file"] is True


def test_try_welcome_recovers_a_single_inline_brief_flag_offline():
    detail = {"name": "Welcome!", "category": "misc",
              "description": f"Welcome to the CTF. Here is a freebie: {FLAG}. Have fun."}
    r = fastlane.try_welcome(detail, None)
    assert r is not None and r["flag"] == FLAG, r
    assert r["klass"] == "welcome" and r["confidence"] == "high" and r["source"] == "description"
    assert r.get("instruction") is None


def test_try_welcome_will_not_promote_the_format_example_as_a_flag():
    # two flag-shaped values (or a placeholder) is ambiguous: _first_flag returns neither, so the
    # auto-trigger stands down to a human step rather than guessing.
    detail = {"name": "Welcome", "category": "misc",
              "description": f"Flags look like CSCTF{{example}}. Your real one is {FLAG} somewhere else."}
    r = fastlane.try_welcome(detail, None)
    assert r is not None and r["flag"] == FLAG  # exactly one NON-placeholder value -> still recovered
    # but with a second real value it must stand down
    detail2 = {"name": "Welcome", "category": "misc",
               "description": f"{FLAG} or maybe CSCTF{{another_real_one}}"}
    r2 = fastlane.try_welcome(detail2, None)
    assert r2 is not None and r2["flag"] is None and r2.get("instruction"), r2


def test_try_welcome_gives_a_human_step_for_a_profile_challenge_without_an_inline_flag():
    detail = {"name": "Where U From", "category": "misc",
              "description": "Update your team profile with your country to get the flag."}
    r = fastlane.try_welcome(detail, None, base_url="https://board.example.test")
    assert r is not None and r["flag"] is None, r
    assert r["klass"] == "platform-profile"
    assert "profile" in r["instruction"] and "board.example.test" in r["instruction"]
    assert "by hand" in r["instruction"]           # the submission is never scripted


def test_try_welcome_returns_none_for_a_non_welcome_challenge_even_with_a_brief_flag():
    # a real crypto challenge whose brief quotes the format must NOT be auto-triggered: the auto-trigger
    # is what lets intake keep a brief flag, so it must fire only on the welcome/profile classes.
    detail = {"name": "RSA Warmup", "category": "crypto",
              "description": f"Decrypt the ciphertext. Format: {FLAG}"}
    assert fastlane.try_welcome(detail, None) is None


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
