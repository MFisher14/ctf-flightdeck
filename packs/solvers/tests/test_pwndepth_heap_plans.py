"""Deterministic, non-circular tests for the modern heap depth planner."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

import pwndepth_heap_plans as heap


BASE = 0x555555559000


def _phase_memory(plan: heap.HeapDepthPlan, phase: str) -> dict[int, int]:
    return {fact.address: fact.value for fact in plan.facts if fact.phase == phase}


def _water(**overrides) -> heap.HeapDepthPlan:
    config = {
        "glibc_version": "2.41",
        "tcache_chunk_header_addr": BASE,
        "relative_chunk_addr": BASE + 0x2A0,
        "small_start_addr": BASE + 0x350,
        "small_end_addr": BASE + 0x400,
        "primitive": "uaf",
        "tcache_capacity": 7,
        "guards_present": True,
        "can_forge_chunk_sizes": True,
        "can_restore_chunk_sizes": True,
        "can_corrupt_link_lsb": True,
        "can_free_interior_headers": True,
        "allow_bruteforce": False,
    }
    config.update(overrides)
    return heap.build_house_of_water_plan(**config)


def _large(**overrides) -> heap.HeapDepthPlan:
    config = {
        "glibc_version": "2.35",
        "existing_chunk_addr": 0x555555570000,
        "existing_chunk_size": 0x430,
        "victim_chunk_addr": 0x555555572000,
        "victim_chunk_size": 0x420,
        "target_addr": 0x7FFFF7FC5000,
        "bin_head_addr": 0x7FFFF7FC4A00,
        "sort_request": 0x438,
        "guards_present": True,
        "target_writable": True,
        "arena_managed": True,
    }
    config.update(overrides)
    return heap.build_large_bin_plan(**config)


def _banana_large(**overrides) -> heap.HeapDepthPlan:
    return _large(
        existing_chunk_size=0x4E0,
        victim_chunk_size=0x4D0,
        sort_request=0x4E8,
        **overrides,
    )


def test_house_of_water_matches_published_smallbin_geometry() -> None:
    """Reference values come from how2heap's hand-described tcache structure layout."""

    plan = _water()
    values = plan.computed_dict()
    assert plan.technique == "house-of-water-smallbin"
    assert values["fake_chunk_header"] == BASE + 0x200
    assert values["fake_user_return"] == BASE + 0x210
    assert values["relative_chunk_header"] == BASE + 0x290
    assert values["small_start_header"] == BASE + 0x340
    assert values["small_end_header"] == BASE + 0x3F0
    assert values["tcache_0x320_head"] == BASE + 0x210
    assert values["tcache_0x330_head"] == BASE + 0x218
    assert values["bruteforce"] is False

    writes = {(item.phase, item.address): (item.value, item.width) for item in plan.writes}
    assert writes[("forge-330", BASE + 0x338)] == (0x331, 8)
    assert writes[("restore-330", BASE + 0x348)] == (0x91, 8)
    assert writes[("forge-320", BASE + 0x3E8)] == (0x321, 8)
    assert writes[("restore-320", BASE + 0x3F8)] == (0x91, 8)
    assert writes[("link-smallbin", BASE + 0x350)] == (0, 1)
    assert writes[("link-smallbin", BASE + 0x408)] == (0, 1)

    forged = _phase_memory(plan, "forged-heads")
    assert forged[BASE + 0x210] == BASE + 0x3F0
    assert forged[BASE + 0x218] == BASE + 0x340
    assert heap.verify_plan_phase(plan, forged, phase="forged-heads")

    linked = _phase_memory(plan, "linked")
    assert linked[BASE + 0x350] == BASE + 0x200
    assert linked[BASE + 0x408] == BASE + 0x200
    assert heap.verify_plan_phase(plan, linked, phase="linked")


def test_house_of_water_rejects_guessing_and_wrong_feng_shui() -> None:
    with pytest.raises(heap.PwnDepthHeapError, match="brute-force"):
        _water(allow_bruteforce=True)
    with pytest.raises(heap.PwnDepthHeapError, match="0x90/0x20 geometry"):
        _water(small_start_addr=BASE + 0x360)
    with pytest.raises(heap.PwnDepthHeapError, match="requires guards_present"):
        _water(guards_present=False)
    with pytest.raises(heap.PwnDepthHeapError, match="primitive"):
        _water(primitive="guess")
    with pytest.raises(heap.PwnDepthHeapError, match="interior"):
        _water(can_free_interior_headers=False)


def test_largebin_index_matches_glibc_macro_boundaries() -> None:
    # Direct evaluations of glibc's largebin_index_64 macro, independent of the planner.
    assert heap.largebin_index_64(0x400) == 64       # 48 + (0x400 >> 6)
    assert heap.largebin_index_64(0xC00) == 96       # final first-tier value
    assert heap.largebin_index_64(0xC40) == 97       # 91 + (0xC40 >> 9)
    assert heap.largebin_index_64(0x2800) == 111     # 110 + (0x2800 >> 12)
    assert heap.largebin_index_64(0x10000) == 121    # 119 + (0x10000 >> 15)
    assert heap.largebin_index_64(0x100000) == 126


def test_post_230_largebin_models_two_chunks_reciprocals_and_constrained_write() -> None:
    plan = _large()
    values = plan.computed_dict()
    existing = 0x555555570000
    victim = 0x555555572000
    target = 0x7FFFF7FC5000
    head = 0x7FFFF7FC4A00
    assert values["largebin_index"] == 64
    assert values["sort_chunk_size"] == 0x440
    assert values["forged_bk_nextsize"] == target - 0x20
    assert values["written_value"] == victim
    assert plan.writes == (
        heap.SparseWrite("arm", "existing.bk_nextsize", existing + 0x28, target - 0x20, 8),
    )

    pre = _phase_memory(plan, "pre")
    assert pre[existing + 0x10] == head
    assert pre[existing + 0x18] == head
    assert pre[existing + 0x20] == existing
    assert pre[existing + 0x28] == existing
    assert pre[head + 0x10] == existing
    assert pre[head + 0x18] == existing
    assert heap.verify_plan_phase(plan, pre, phase="pre")

    armed = _phase_memory(plan, "armed")
    assert armed[existing + 0x28] == target - 0x20
    assert heap.verify_plan_phase(plan, armed, phase="armed")
    assert heap.verify_plan_phase(plan, {target: victim}, phase="triggered")


def test_largebin_fails_closed_on_wrong_order_bin_or_state_assertions() -> None:
    with pytest.raises(heap.PwnDepthHeapError, match="strictly larger"):
        _large(existing_chunk_size=0x420, victim_chunk_size=0x430)
    with pytest.raises(heap.PwnDepthHeapError, match="same large-bin"):
        _large(existing_chunk_size=0x520, victim_chunk_size=0x430)
    with pytest.raises(heap.PwnDepthHeapError, match="guard"):
        _large(guards_present=False)
    with pytest.raises(heap.PwnDepthHeapError, match="writable"):
        _large(target_writable=False)
    with pytest.raises(heap.PwnDepthHeapError, match="arena-managed"):
        _large(arena_managed=False)
    with pytest.raises(heap.PwnDepthHeapError, match="sort_request"):
        _large(sort_request=0x418)


def _banana_layout() -> heap.BananaLayout:
    return heap.BananaLayout(
        # Extracted from the csctf-pwn glibc 2.39 debug type; the Docker oracle uses it live.
        size=0x4B8,
        l_addr=0x00,
        l_real=0x28,
        l_next=0x18,
        l_ns=0x30,
        l_init_called=0x354,
        l_init_called_mask=0x10,
        l_info=0x40,
        l_info_slots=84,
        l_init_called_width=4,
    )


def test_house_of_banana_binds_largebin_value_to_profiled_link_map() -> None:
    fake = 0x555555572000
    link_slot = 0x7FFFF7FC5000
    replaced = 0x7FFFF7FFD000
    next_map = 0x7FFFF7FFC000
    plan = heap.build_house_of_banana_plan(
        glibc_version="2.39",
        large_bin_plan=_banana_large(
            glibc_version="2.39", victim_chunk_addr=fake, target_addr=link_slot
        ),
        layout=_banana_layout(),
        fake_link_map_addr=fake,
        loader_link_slot_addr=link_slot,
        replaced_map_addr=replaced,
        replaced_map_next_addr=next_map,
        fini_dyn_addr=0x555555580000,
        fini_array_size_dyn_addr=0x555555580020,
        fini_array_addr=0x555555580040,
        call_target=0x7FFFF7E12340,
        namespace_nloaded=4,
        real_maps_before_fake=0,
        real_maps_after_fake=3,
        l_addr=0,
        namespace_id=0,
        cleanup_trigger="exit",
        replaces_real_map=True,
        zeroed_backing=True,
        sort_dependencies_safe=True,
        audit_modules_present=False,
    )
    assert plan.technique == "house-of-banana-dl-fini"
    armed = _phase_memory(plan, "armed")
    layout = _banana_layout()
    assert armed[fake + layout.l_addr] == 0
    assert armed[fake + layout.l_real] == fake
    assert armed[fake + layout.l_next] == next_map
    assert armed[fake + layout.l_ns] == 0
    assert armed[fake + layout.l_init_called] == 0x10
    assert armed[fake + layout.l_info + heap.DT_FINI_ARRAY * 8] == 0x555555580000
    assert armed[fake + layout.l_info + heap.DT_FINI_ARRAYSZ * 8] == 0x555555580020
    assert armed[0x555555580000] == heap.DT_FINI_ARRAY
    assert armed[0x555555580008] == 0x555555580040
    assert armed[0x555555580020] == heap.DT_FINI_ARRAYSZ
    assert armed[0x555555580028] == 8
    assert armed[0x555555580040] == 0x7FFFF7E12340
    assert heap.verify_plan_phase(plan, armed, phase="armed")

    triggered = _phase_memory(plan, "triggered")
    assert triggered[link_slot] == fake
    assert heap.verify_plan_phase(plan, triggered, phase="triggered")
    loader_pre = _phase_memory(plan, "loader-pre")
    assert loader_pre[link_slot] == replaced
    assert loader_pre[replaced + layout.l_next] == next_map
    assert heap.verify_plan_phase(plan, loader_pre, phase="loader-pre")


def test_house_of_banana_rejects_layout_target_and_cleanup_mismatches() -> None:
    common = dict(
        glibc_version="2.39",
        large_bin_plan=_banana_large(glibc_version="2.39"),
        layout=_banana_layout(),
        fake_link_map_addr=0x555555572000,
        loader_link_slot_addr=0x7FFFF7FC5000,
        replaced_map_addr=0x7FFFF7FFD000,
        replaced_map_next_addr=0x7FFFF7FFC000,
        fini_dyn_addr=0x555555580000,
        fini_array_size_dyn_addr=0x555555580020,
        fini_array_addr=0x555555580040,
        call_target=0x7FFFF7E12340,
        namespace_nloaded=4,
        real_maps_before_fake=0,
        real_maps_after_fake=3,
        cleanup_trigger="exit",
        replaces_real_map=True,
        zeroed_backing=True,
        sort_dependencies_safe=True,
        audit_modules_present=False,
    )
    with pytest.raises(heap.PwnDepthHeapError, match="large-bin target"):
        heap.build_house_of_banana_plan(**{**common, "loader_link_slot_addr": 0x7FFFF7FC6000})
    with pytest.raises(heap.PwnDepthHeapError, match="chain count"):
        heap.build_house_of_banana_plan(**{**common, "namespace_nloaded": 5})
    with pytest.raises(heap.PwnDepthHeapError, match="too small"):
        heap.build_house_of_banana_plan(
            **{**common, "large_bin_plan": _large(glibc_version="2.39")}
        )
    with pytest.raises(heap.PwnDepthHeapError, match="init_called_mask"):
        heap.build_house_of_banana_plan(
            **{**common, "layout": replace(_banana_layout(), l_init_called_mask=0x08)}
        )
    old = heap.build_house_of_banana_plan(
        **{
            **common,
            "glibc_version": "2.35",
            "large_bin_plan": _banana_large(glibc_version="2.35"),
            "layout": replace(_banana_layout(), l_init_called_mask=0x08),
        }
    )
    assert old.computed_dict()["l_init_called_mask"] == 0x08
    overlapping = heap.BananaLayout(
        size=0x300, l_addr=0, l_real=8, l_next=0x10, l_ns=0x18,
        l_init_called=0x20, l_init_called_mask=0x08, l_info=0x20, l_info_slots=64,
    )
    with pytest.raises(heap.PwnDepthHeapError, match="overlap"):
        heap.build_house_of_banana_plan(**{**common, "layout": overlapping})


def test_inverse_verifier_reports_missing_and_mutated_words() -> None:
    plan = _large()
    armed = _phase_memory(plan, "armed")
    missing = dict(armed)
    missing.pop(next(iter(missing)))
    with pytest.raises(heap.PwnDepthHeapError, match="missing"):
        heap.verify_plan_phase(plan, missing, phase="armed")
    mutated = dict(armed)
    address = next(iter(mutated))
    mutated[address] ^= 8
    with pytest.raises(heap.PwnDepthHeapError, match="mismatch"):
        heap.verify_plan_phase(plan, mutated, phase="armed")
    with pytest.raises(heap.PwnDepthHeapError, match="no verifiable facts"):
        heap.verify_plan_phase(plan, armed, phase="unknown")


def test_malformed_values_raise_only_declared_error() -> None:
    malformed = (None, True, -1, [], {}, object(), "not-a-number")
    for value in malformed:
        with pytest.raises(heap.PwnDepthHeapError):
            heap.largebin_index_64(value)  # type: ignore[arg-type]
        with pytest.raises(heap.PwnDepthHeapError):
            _large(existing_chunk_addr=value)
    for version in ("2.34", "2.42", "x", None, True):
        with pytest.raises(heap.PwnDepthHeapError):
            _water(glibc_version=version)
    with pytest.raises(heap.PwnDepthHeapError):
        _water(primitive=[])


def test_guarded_json_cli_and_basename_import(tmp_path, capsys) -> None:
    config = {
        "glibc_version": "2.41",
        "existing_chunk_addr": "0x555555570000",
        "existing_chunk_size": "0x430",
        "victim_chunk_addr": "0x555555572000",
        "victim_chunk_size": "0x420",
        "target_addr": "0x7ffff7fc5000",
        "bin_head_addr": "0x7ffff7fc4a00",
        "sort_request": "0x438",
        "guards_present": True,
        "target_writable": True,
        "arena_managed": True,
    }
    path = tmp_path / "large.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    assert heap.main(["largebin", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["technique"] == "large-bin-post-2.30"
    assert report["computed"]["written_value"] == 0x555555572000
    assert heap.main(["--help"]) == 0
    capsys.readouterr()
    assert heap.main([]) == 2
    assert heap.main(["water", str(tmp_path / "missing.json")]) == 2
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert heap.main(["water", str(broken)]) == 2

