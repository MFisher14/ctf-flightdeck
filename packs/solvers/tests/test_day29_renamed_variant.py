"""B-040: the Day 29 variant reader follows a RENAMED role tag through the build-word seed.

The real Day 29 delivers the two optimization builds as ``*-O3.elf`` / ``*-O0.elf`` and the questions
often name the member ("basename ends O3.elf"). A later variant may rename the tag (fast/slow) AND drop
the naming sentence. d29.py then has only the build word `optimized` / `unoptimized`, and must read the
right member from the seed store (solvers/binary/build_conventions.json, B-040) instead of a hard-coded
day table. This freezes that: with the seed mapping optimized -> fast.elf the renamed member is read;
without the seed (the built-in O3/O0 default cannot match the renamed files) the build id is left for
generic.py, so nothing is guessed.
"""
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))

import d29  # noqa: E402


def _record(obj, key):
    plain = json.dumps(obj, separators=(",", ":")).encode()
    return (b"HCFG" + struct.pack("<BBHI", 1, key, len(plain), zlib.crc32(plain))
            + bytes(value ^ key for value in plain))


def _sample(obj, key):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", header, 16, 2)
    struct.pack_into("<H", header, 18, 62)
    return bytes(header) + _record(obj, key)


FAST = {"campaign": "BR29-FAST", "domain": "fast.invalid", "url": "https://fast.invalid/a", "mutex": "F"}
SLOW = {"campaign": "BR29-SLOW", "domain": "slow.invalid", "url": "https://slow.invalid/a", "mutex": "S"}
# renamed tags: no O3/O0 anywhere in the member names
FILES = {"d29--sample-fast.elf": _sample(FAST, 0x11), "d29--sample-slow.elf": _sample(SLOW, 0x22)}


def _q(build, field):
    # deliberately no "basename ends ..." sentence: the member must be found from the seed alone
    qid = f"d29_analysis_{build}_config_{field}"
    return {"id": qid, "qid": qid, "question": f"Submit the HCFG record's {field} property.",
            "answer_format": {"kind": "exact_text"}}


@pytest.fixture
def _clear_conv_cache():
    d29._CONV_CACHE.clear()
    yield
    d29._CONV_CACHE.clear()


def test_renamed_tags_are_read_through_the_seed(tmp_path, monkeypatch, _clear_conv_cache):
    seed = tmp_path / "build_conventions.json"
    seed.write_text(json.dumps({"optimized": ["fast.elf"], "unoptimized": ["slow.elf"]}))
    monkeypatch.setattr(d29, "CONV_PATH", seed)
    questions = [_q("optimized", f) for f in ("campaign", "domain", "url", "mutex")]
    questions += [_q("unoptimized", f) for f in ("campaign", "domain", "url", "mutex")]
    got = d29.answers(questions, dict(FILES), {"set": 1})
    for field in ("campaign", "domain", "url", "mutex"):
        assert got[f"d29_analysis_optimized_config_{field}"] == FAST[field]
        assert got[f"d29_analysis_unoptimized_config_{field}"] == SLOW[field]


def test_without_the_seed_the_renamed_member_is_left_for_generic(tmp_path, monkeypatch, _clear_conv_cache):
    # a seed that does not know the renamed tag -> the built-in O3/O0 default cannot match -> no answer,
    # never a guess at which renamed member is the optimized build.
    seed = tmp_path / "build_conventions.json"
    seed.write_text(json.dumps({"optimized": ["o3.elf"], "unoptimized": ["o0.elf"]}))
    monkeypatch.setattr(d29, "CONV_PATH", seed)
    got = d29.answers([_q("optimized", "campaign")], dict(FILES), {"set": 1})
    assert "d29_analysis_optimized_config_campaign" not in got


def test_the_question_text_still_wins_over_the_seed(tmp_path, monkeypatch, _clear_conv_cache):
    # an explicit "basename ends" sentence overrides the seed, so a one-off rename in the text is followed
    seed = tmp_path / "build_conventions.json"
    seed.write_text(json.dumps({"optimized": ["slow.elf"]}))   # a wrong seed
    monkeypatch.setattr(d29, "CONV_PATH", seed)
    q = _q("optimized", "campaign")
    q["question"] = "Use the unique d29-- member whose basename ends fast.elf. Submit the campaign."
    got = d29.answers([q], dict(FILES), {"set": 1})
    assert got["d29_analysis_optimized_config_campaign"] == FAST["campaign"]


def test_a_malformed_seed_falls_back_to_the_built_in_default_loudly(tmp_path, monkeypatch, capsys,
                                                                     _clear_conv_cache):
    seed = tmp_path / "build_conventions.json"
    seed.write_text("{ not json")
    monkeypatch.setattr(d29, "CONV_PATH", seed)
    files = {"d29--sample-O3.elf": _sample(FAST, 0x11), "d29--sample-O0.elf": _sample(SLOW, 0x22)}
    got = d29.answers([_q("optimized", "campaign")], files, {"set": 1})
    assert got["d29_analysis_optimized_config_campaign"] == FAST["campaign"]   # default O3/O0 still read
    assert "build_conventions.json" in capsys.readouterr().err                 # and it said so


def test_the_shipped_seed_matches_the_built_in_default():
    # the tracked seed must agree with d29's in-code default, so removing the file changes nothing.
    data = json.loads((REPO / "solvers" / "binary" / "build_conventions.json").read_text())
    assert data.get("optimized") == d29._DEFAULT_BUILD_SUFFIX["optimized"]
    assert data.get("unoptimized") == d29._DEFAULT_BUILD_SUFFIX["unoptimized"]
