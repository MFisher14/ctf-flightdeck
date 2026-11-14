"""Published-source vectors for the glibc 2.40--2.43 bin-path planner.

Expected values below are literal translations or boundary evaluations of the
tagged GNU libc macros, not values produced by the engine under test.  Primary
anchors are glibc-2.42 malloc.c lines 292, 1319, 1566, 3163, 3465 and 5588,
and their glibc-2.43 counterparts at lines 294, 1254, 1542, 3003, 3301 and
5081 in the official Sourceware repository.
"""
from __future__ import annotations

import json

import pytest

import wpgap_glibc_binpath as planner


def reference_largebin_index_64(size: int) -> int:
    """Independent literal translation of glibc's largebin_index_64 macro."""

    if (size >> 6) <= 48:
        return 48 + (size >> 6)
    if (size >> 9) <= 20:
        return 91 + (size >> 9)
    if (size >> 12) <= 10:
        return 110 + (size >> 12)
    if (size >> 15) <= 4:
        return 119 + (size >> 15)
    if (size >> 18) <= 2:
        return 124 + (size >> 18)
    return 126


def components(plan: planner.AllocatorPathPlan) -> list[str]:
    return [step.component for step in plan.allocation_path]


def free_components(plan: planner.AllocatorPathPlan) -> list[str]:
    return [step.component for step in plan.free_path]


def test_release_profiles_match_upstream_transition_commits() -> None:
    p40 = planner.release_profile("2.40")
    p41 = planner.release_profile("2.41")
    p42 = planner.release_profile("2.42")
    p43 = planner.release_profile("2.43")

    assert (p40.tcache_counter_field, p40.default_tcache_count) == ("counts", 7)
    assert p40.fastbins_present is True
    assert p40.calloc_tcache_first is False
    assert p40.ordinary_small_free_staging == "unsorted-after-coalescing"

    assert p41.calloc_tcache_first is True
    assert p41.ordinary_small_free_staging == "smallbin-after-coalescing"

    assert p42.tcache_total_bins == 76
    assert p42.tcache_counter_field == "num_slots"
    assert p42.tcache_counter_semantics == "remaining-slots-down-counter"
    assert p42.all_bin_double_free_scan is True
    assert p42.fastbins_present is True
    assert p42.large_tcache_selection.startswith("first-chunk-greater")

    assert p43.default_tcache_count == 16
    assert p43.fastbins_present is False
    assert p43.default_max_fast_chunk is None
    assert p43.large_tcache_selection == "exact-chunk-size-within-sorted-bin"


@pytest.mark.parametrize(
    "value",
    ["2.39", "2.44", "2.42.1", "2.42-ubuntu", "release/2.42", "", None, True],
)
def test_unknown_versions_and_backport_labels_are_declined(value: object) -> None:
    with pytest.raises(planner.WPGAPGlibcError):
        planner.release_profile(value)  # type: ignore[arg-type]
    with pytest.raises(planner.WPGAPGlibcError):
        planner.plan_allocation(value, 1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("req", "chunk"),
    [
        (0, 0x20),
        (24, 0x20),
        (25, 0x30),
        (120, 0x80),
        (121, 0x90),
        (1000, 0x3F0),
        (1001, 0x400),
        (1016, 0x400),
        (1017, 0x410),
        (1032, 0x410),
        (1033, 0x420),
        (2024, 0x7F0),
        (2025, 0x800),
    ],
)
def test_request_normalization_matches_published_macro_vectors(
    req: int, chunk: int
) -> None:
    assert planner.plan_allocation("2.43", req).chunk_size == chunk


@pytest.mark.parametrize(
    "chunk",
    [0x400, 0xC30, 0xC40, 0x29F0, 0x2A00, 0xA000, 0x28000, 0x40000, 0x80000],
)
def test_arena_largebin_indices_match_independent_macro(chunk: int) -> None:
    assert planner.largebin_index_64(chunk) == reference_largebin_index_64(chunk)


def test_tcache_small_geometry_overlaps_arena_largebin_geometry() -> None:
    small = planner.plan_allocation("2.43", 0x3E8)
    assert (small.chunk_size, small.tcache_bin_index) == (0x3F0, 61)
    assert (small.arena_bin_kind, small.arena_bin_index) == ("smallbin", 63)

    boundary = planner.plan_allocation("2.43", 0x3E9)
    assert (boundary.chunk_size, boundary.tcache_bin_index) == (0x400, 62)
    assert (boundary.arena_bin_kind, boundary.arena_bin_index) == ("largebin", 64)

    last_tcache_small = planner.plan_allocation("2.43", 0x408)
    assert (last_tcache_small.chunk_size, last_tcache_small.tcache_bin_index) == (0x410, 63)
    assert (last_tcache_small.arena_bin_kind, last_tcache_small.arena_bin_index) == (
        "largebin",
        64,
    )


def test_release_default_tcache_boundaries_preserve_242_tag_bug() -> None:
    for version in ("2.40", "2.41", "2.43"):
        plan = planner.plan_allocation(version, 0x408)
        assert plan.tcache_bin_index == 63
        assert plan.tcache_size_eligible is True

    assert planner.plan_allocation("2.42", 0x3F8).tcache_size_eligible is True
    excluded = planner.plan_allocation("2.42", 0x3F9)
    assert (excluded.chunk_size, excluded.tcache_bin_index) == (0x410, 63)
    assert excluded.tcache_size_eligible is False
    with pytest.raises(planner.WPGAPGlibcError):
        planner.plan_allocation("2.42", 0x408, tcache_state="hit")


def test_large_tcache_tunable_boundaries_and_selection_rules() -> None:
    tag_excluded = planner.plan_allocation("2.42", 0x418, tcache_max=0x418)
    tag_included = planner.plan_allocation("2.42", 0x418, tcache_max=0x419)
    fixed_included = planner.plan_allocation("2.43", 0x418, tcache_max=0x409)

    assert (tag_excluded.chunk_size, tag_excluded.tcache_bin_index) == (0x420, 64)
    assert tag_excluded.tcache_size_eligible is False
    assert tag_included.tcache_size_eligible is True
    assert tag_included.tcache_selection_rule.startswith("first-chunk-greater")
    assert tag_included.large_tcache_for_request is True
    assert fixed_included.tcache_size_eligible is True
    assert fixed_included.tcache_selection_rule == "exact-chunk-size-within-sorted-bin"

    maximum = planner.plan_allocation(
        "2.43", 0x3FFFE8, tcache_max=0x3FFFE8
    )
    assert (maximum.chunk_size, maximum.tcache_bin_index) == (0x3FFFF0, 75)
    assert maximum.tcache_size_eligible is True
    with pytest.raises(planner.WPGAPGlibcError):
        planner.plan_allocation("2.43", 1, tcache_max=0x3FFFE9)


def test_ordered_fastbin_and_arena_paths_reflect_243_removal() -> None:
    old = planner.plan_allocation("2.42", 0x78, tcache_state="miss")
    assert (old.chunk_size, old.fastbin_index) == (0x80, 6)
    assert components(old) == [
        "tcache",
        "fastbin",
        "smallbin",
        "unsorted-scan",
        "binmap-search",
        "top",
        "sysmalloc",
    ]

    outside_fast = planner.plan_allocation("2.42", 0x79, tcache_state="miss")
    assert (outside_fast.chunk_size, outside_fast.fastbin_index) == (0x90, None)

    current = planner.plan_allocation("2.43", 0x78, tcache_state="miss")
    assert current.fastbin_index is None
    assert "fastbin" not in components(current)

    old_large = planner.plan_allocation("2.42", 0x418)
    new_large = planner.plan_allocation("2.43", 0x418)
    assert "malloc-consolidate" in components(old_large)
    assert "malloc-consolidate" not in components(new_large)
    assert components(new_large)[1:3] == ["unsorted-scan", "largebin"]


def test_free_staging_distinguishes_240_241_and_fastbin_removal() -> None:
    old = planner.plan_allocation("2.40", 0x100, tcache_count=0)
    newer = planner.plan_allocation("2.41", 0x100, tcache_count=0)
    current = planner.plan_allocation("2.43", 0x100, tcache_count=0)

    old_stage = next(step for step in old.free_path if step.component == "ordinary-free-staging")
    newer_stage = next(
        step for step in newer.free_path if step.component == "ordinary-free-staging"
    )
    current_stage = next(
        step for step in current.free_path if step.component == "ordinary-free-staging"
    )
    assert old_stage.bin_kind == "unsorted"
    assert "including a small result" in old_stage.outcome
    assert newer_stage.bin_kind == "smallbin-or-unsorted"
    assert "small result -> smallbin" in newer_stage.outcome
    assert current_stage.bin_kind == "smallbin-or-unsorted"

    old_fast = planner.plan_allocation("2.42", 0x78, tcache_count=0)
    new_fast = planner.plan_allocation("2.43", 0x78, tcache_count=0)
    assert "fastbin" in free_components(old_fast)
    assert "fastbin" not in free_components(new_fast)


def test_calloc_240_bypasses_direct_tcache_but_241_uses_it() -> None:
    old = planner.plan_allocation("2.40", 0x20, api="calloc")
    assert old.tcache_size_eligible is True
    assert old.tcache_checked is False
    assert old.allocation_path[0].component == "tcache-bypass"
    with pytest.raises(planner.WPGAPGlibcError):
        planner.plan_allocation("2.40", 0x20, api="calloc", tcache_state="hit")

    new = planner.plan_allocation(
        "2.41", 0x20, api="calloc", tcache_state="hit"
    )
    assert new.tcache_checked is True
    assert new.confirmed_allocation_source == "tcache[1]"


def test_official_dead_or_alive_sizes_form_a_non_circular_scenario_check() -> None:
    # The official challenge used 2.35.  These source-published sizes are
    # transposed only as a routing scenario for the supported modern tags.
    assert planner.plan_allocation("2.40", 0x20).chunk_size == 0x30
    assert planner.plan_allocation("2.40", 26).chunk_size == 0x30
    assert planner.plan_allocation("2.40", 100).chunk_size == 0x70

    default = planner.plan_allocation("2.42", 0x418)
    assert default.chunk_size == 0x420
    assert (default.tcache_bin_kind, default.tcache_bin_index) == ("large", 64)
    assert default.tcache_size_eligible is False
    assert (default.arena_bin_kind, default.arena_bin_index) == ("largebin", 64)
    stage = next(
        step for step in default.free_path if step.component == "ordinary-free-staging"
    )
    assert "large result -> unsorted" in stage.outcome

    tuned42 = planner.plan_allocation("2.42", 0x418, tcache_max=0x419)
    tuned43 = planner.plan_allocation("2.43", 0x418, tcache_max=0x409)
    assert tuned42.large_tcache_for_request is True
    assert tuned43.large_tcache_for_request is True


def test_caller_hit_miss_facts_resolve_only_the_tcache_source() -> None:
    unknown = planner.plan_allocation("2.43", 0x20)
    hit = planner.plan_allocation("2.43", 0x20, tcache_state="hit")
    miss = planner.plan_allocation("2.43", 0x20, tcache_state="miss")
    assert unknown.confirmed_allocation_source is None
    assert hit.confirmed_allocation_source == "tcache[1]"
    assert miss.confirmed_allocation_source is None
    assert "fall through" in miss.allocation_path[0].outcome

    disabled = planner.plan_allocation("2.43", 0x20, tcache_count=0)
    assert disabled.tcache_size_eligible is True
    assert disabled.tcache_checked is False
    with pytest.raises(planner.WPGAPGlibcError):
        planner.plan_allocation("2.43", 0x20, tcache_count=0, tcache_state="hit")


@pytest.mark.parametrize(
    "call",
    [
        lambda: planner.plan_allocation("2.43", True),
        lambda: planner.plan_allocation("2.43", -1),
        lambda: planner.plan_allocation("2.43", planner.MAX_REQUEST + 1),
        lambda: planner.plan_allocation("2.43", 1, api="realloc"),
        lambda: planner.plan_allocation("2.43", 1, tcache_state="present"),
        lambda: planner.plan_allocation("2.43", 1, tcache_count=-1),
        lambda: planner.plan_allocation("2.43", 1, tcache_count=65536),
        lambda: planner.plan_allocation("2.43", 1, tcache_max=True),
        lambda: planner.largebin_index_64(None),
        lambda: planner.largebin_index_64(0x3F0),
        lambda: planner.largebin_index_64(0x401),
    ],
)
def test_all_public_malformed_inputs_raise_only_declared_error(call) -> None:
    with pytest.raises(planner.WPGAPGlibcError):
        call()


def test_result_is_deterministic_address_free_and_offline() -> None:
    plan = planner.plan_allocation(
        "2.43", 0x808, tcache_max=0x1000, tcache_state="miss"
    )
    one = json.dumps(plan.as_dict(), sort_keys=True)
    two = json.dumps(plan.as_dict(), sort_keys=True)
    assert one == two
    assert plan.address_assumptions == ()
    assert plan.offline is True
    assert plan.network_requests == 0
    assert plan.executed is False
    assert plan.confirmed_allocation_source is None


def test_guarded_cli_returns_codes_and_deterministic_json(capsys) -> None:
    assert planner.main(["--help"]) == 0
    capsys.readouterr()
    assert planner.main([]) == 2
    capsys.readouterr()
    assert planner.main(["plan", "2.43", "not-an-int"]) == 2
    capsys.readouterr()
    assert planner.main(["profile", "2.42.1"]) == 2
    capsys.readouterr()

    args = [
        "plan",
        "2.43",
        "0x418",
        "--tcache-max",
        "0x409",
        "--tcache-state",
        "hit",
    ]
    assert planner.main(args) == 0
    first = capsys.readouterr().out
    assert planner.main(args) == 0
    second = capsys.readouterr().out
    assert first == second
    parsed = json.loads(first)
    assert parsed["chunk_size"] == 0x420
    assert parsed["tcache_bin_index"] == 64
    assert parsed["confirmed_allocation_source"] == "tcache[64]"
