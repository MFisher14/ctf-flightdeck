"""Source-derived vectors for the glibc 2.40--2.43 transition planner."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import research_wp_glibc_modern as modern  # noqa: E402


def test_profiles_capture_release_transitions() -> None:
    p40 = modern.profile_for("2.40")
    p41 = modern.profile_for("2.41")
    p42 = modern.profile_for("2.42")
    p43 = modern.profile_for("2.43")

    assert p40.calloc_uses_tcache is False
    assert p41.calloc_uses_tcache is True
    assert p41.tcache_total_bins == 64
    assert p41.counter_field == "counts"

    assert p42.tcache_small_bins == 64
    assert p42.tcache_large_bins == 12
    assert p42.tcache_total_bins == 76
    assert p42.counter_field == "num_slots"
    assert p42.counter_semantics == "remaining-slots-down-counter"
    assert p42.all_bin_double_free_scan is True
    assert p42.fastbins_present is True
    assert p42.default_tcache_count == 7

    assert p43.fastbins_present is False
    assert p43.default_tcache_count == 16
    assert p43.safe_linking is True


@pytest.mark.parametrize("value", ["2.39", "2.44", "3.0", "2", "x", object()])
def test_profile_rejects_unknown_or_malformed_versions(value) -> None:
    with pytest.raises(modern.ResearchWPGlibcError):
        modern.profile_for(value)


def test_request2size_matches_upstream_macro_boundary_vectors() -> None:
    # Independent evaluations of (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~mask,
    # with the ABI MINSIZE floor.
    assert modern.request2size(0, bits=64) == 0x20
    assert modern.request2size(0x18, bits=64) == 0x20
    assert modern.request2size(0x19, bits=64) == 0x30
    assert modern.request2size(0x3F8, bits=64) == 0x400
    assert modern.request2size(0x3F9, bits=64) == 0x410
    assert modern.request2size(0x408, bits=64) == 0x410

    assert modern.request2size(0, bits=32) == 0x10
    assert modern.request2size(0x0C, bits=32) == 0x10
    assert modern.request2size(0x0D, bits=32) == 0x18


def test_small_and_logarithmic_large_bin_boundaries_match_glibc_macros() -> None:
    assert modern.tcache_index(0x20, glibc_version="2.42") == (0, "small")
    assert modern.tcache_index(0x410, glibc_version="2.42") == (63, "small")
    # large_csize2tidx(nb) = 64 + clz(0x410) - clz(nb)
    assert modern.tcache_index(0x420, glibc_version="2.42") == (64, "large")
    assert modern.tcache_index(0x7F0, glibc_version="2.42") == (64, "large")
    assert modern.tcache_index(0x800, glibc_version="2.42") == (65, "large")
    assert modern.tcache_index(0x1000, glibc_version="2.42") == (66, "large")
    assert modern.tcache_index(0x200000, glibc_version="2.42") == (75, "large")

    with pytest.raises(modern.ResearchWPGlibcError, match="no large"):
        modern.tcache_index(0x420, glibc_version="2.41")
    with pytest.raises(modern.ResearchWPGlibcError, match="outside"):
        modern.tcache_index(0x400000, glibc_version="2.42")


def test_242_tag_and_maintained_branch_ceiling_difference_is_explicit() -> None:
    tag_profile = modern.profile_for("2.42")
    fixed_profile = modern.profile_for(
        "2.42", source_profile=modern.SOURCE_MAINTAINED_242
    )
    assert tag_profile.default_ceiling_kind == "exclusive-normalized-chunk"
    assert tag_profile.default_ceiling_value == 0x408
    assert fixed_profile.default_ceiling_kind == "exclusive-normalized-chunk-plus-one"
    assert fixed_profile.default_ceiling_value == 0x411

    # glibc-2.42 tag compares nb < 0x408: chunk 0x400 passes, 0x410 does not.
    assert modern.plan_tcache("2.42", 0x3F8).tcache_eligible is True
    excluded = modern.plan_tcache("2.42", 0x3F9)
    assert excluded.chunk_size == 0x410
    assert excluded.bin_index == 63
    assert excluded.tcache_eligible is False

    corrected = modern.plan_tcache(
        "2.42", 0x408, source_profile=modern.SOURCE_MAINTAINED_242
    )
    assert corrected.chunk_size == 0x410
    assert corrected.bin_index == 63
    assert corrected.tcache_eligible is True


def test_pre_242_bin_count_and_243_corrected_default_include_last_small_bin() -> None:
    old = modern.plan_tcache("2.41", 0x408)
    assert old.bin_index == 63
    assert old.active_small_bins == 64
    assert old.tcache_eligible is True
    assert old.calloc_uses_same_tcache_route is True

    current = modern.plan_tcache("2.43", 0x408)
    assert current.bin_index == 63
    assert current.tcache_eligible is True
    assert current.fastbin_route_exists is False


def test_large_tcache_requires_explicit_tunable_and_models_strict_tag_threshold() -> None:
    default = modern.plan_tcache("2.42", 0xFF0)
    assert default.chunk_size == 0x1000
    assert default.bin_kind == "large"
    assert default.tcache_eligible is False

    # In the initial tag, setting max=0x1000 stores request2size(max)=0x1010
    # and uses a strict comparison.  The exact configured chunk is excluded,
    # while the immediately lower normalized chunk is included.
    lower = modern.plan_tcache("2.42", 0xFF0, tcache_max=0x1000)
    exact = modern.plan_tcache("2.42", 0x1000, tcache_max=0x1000)
    assert lower.chunk_size == 0x1000 and lower.tcache_eligible is True
    assert exact.chunk_size == 0x1010 and exact.tcache_eligible is False

    corrected = modern.plan_tcache(
        "2.42",
        0x1000,
        tcache_max=0x1000,
        source_profile=modern.SOURCE_MAINTAINED_242,
    )
    assert corrected.chunk_size == 0x1010
    assert corrected.tcache_eligible is True
    assert corrected.effective_exclusive_chunk_ceiling == 0x1011


def test_perthread_layout_vectors_are_source_struct_layouts() -> None:
    old64 = modern.profile_for("2.41", bits=64)
    assert (old64.counter_bytes, old64.entries_offset, old64.entries_bytes) == (
        0x80, 0x80, 0x200,
    )
    assert old64.perthread_struct_size == 0x280
    assert old64.perthread_malloc_chunk_size == 0x290
    assert (old64.entry_next_offset, old64.entry_key_offset, old64.entry_size) == (0, 8, 16)

    new64 = modern.profile_for("2.42", bits=64)
    assert (new64.counter_bytes, new64.entries_offset, new64.entries_bytes) == (
        0x98, 0xA0, 0x260,
    )
    assert new64.perthread_struct_size == 0x300
    assert new64.perthread_malloc_chunk_size == 0x310

    new32 = modern.profile_for("2.42", bits=32)
    assert (new32.counter_bytes, new32.entries_offset, new32.entries_bytes) == (
        0x98, 0x98, 0x130,
    )
    assert new32.perthread_struct_size == 0x1C8
    assert new32.perthread_malloc_chunk_size == 0x1D0
    assert (new32.entry_next_offset, new32.entry_key_offset, new32.entry_size) == (0, 4, 8)


@pytest.mark.parametrize(
    "call",
    [
        lambda: modern.request2size(True),
        lambda: modern.request2size(-1),
        lambda: modern.request2size(1, bits=16),
        lambda: modern.tcache_index(0x21, glibc_version="2.42"),
        lambda: modern.profile_for("2.42", source_profile="trunk"),
        lambda: modern.profile_for("2.43", source_profile=modern.SOURCE_MAINTAINED_242),
        lambda: modern.plan_tcache("2.42", 1, tcache_max=modern.MAX_TCACHE_TUNABLE),
    ],
)
def test_public_boundaries_fail_with_declared_exception(call) -> None:
    with pytest.raises(modern.ResearchWPGlibcError):
        call()


def test_result_is_deterministic_json_and_never_claims_exploitability() -> None:
    plan = modern.plan_tcache("2.43", 0x808, tcache_max=0x1000)
    one = json.dumps(plan.as_dict(), sort_keys=True)
    two = json.dumps(plan.as_dict(), sort_keys=True)
    assert one == two
    assert plan.offline is True and plan.network_requests == 0
    assert plan.exploitability_verified is False


def test_guarded_argparse_cli_returns_codes(capsys) -> None:
    assert modern.main(["--help"]) == 0
    capsys.readouterr()
    assert modern.main([]) == 2
    capsys.readouterr()
    assert modern.main(["plan", "2.42", "not-an-int"]) == 2
    capsys.readouterr()

    assert modern.main(["plan", "2.43", "0x408"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["bin_index"] == 63
    assert output["tcache_eligible"] is True
    assert output["fastbin_route_exists"] is False
