from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import heap_version_matrix as matrix  # noqa: E402
import pwn_verify as verify  # noqa: E402


def test_matrix_explicitly_covers_every_minor_223_through_239() -> None:
    assert matrix.SUPPORTED_VERSIONS == tuple(f"2.{minor}" for minor in range(23, 40))
    assert tuple(matrix.VERSION_MATRIX) == matrix.SUPPORTED_VERSIONS
    for minor in range(23, 40):
        profile = matrix.profile_for(f"2.{minor}.99")
        assert profile.minor == minor
        assert profile.tcache is (minor >= 26)
        assert profile.tcache_key_check is (minor >= 29)
        assert profile.safe_linking is (minor >= 32)
        assert profile.aligned_next_check is (minor >= 32)
        assert profile.malloc_hooks_effective is (minor <= 33)
        assert profile.tcache_entry_words == (0 if minor < 26 else (1 if minor < 29 else 2))
        assert profile.tcache_count == (0 if minor < 26 else 7)
        assert profile.tcache_max_chunk_lp32 == (0 if minor < 26 else 0x208)
        assert "release-tag defaults" in profile.constraints[0]


def test_profile_blocks_roundtrip_for_every_supported_minor() -> None:
    for version in matrix.SUPPORTED_VERSIONS:
        build = matrix.build_allocator_profile_block(version)
        assert build.payload[:4] == b"R5BV"
        assert build.slice("minor") == bytes((int(version.split(".")[1]),))
        flags = build.slice("flags")[0]
        profile = matrix.profile_for(version)
        assert bool(flags & 1) == profile.tcache
        assert bool(flags & 2) == profile.tcache_key_check
        assert bool(flags & 4) == profile.safe_linking
        assert bool(flags & 8) == profile.malloc_hooks_effective
        verify.verify_payload(version, build)


def test_versioned_fastbin_planner_spans_every_minor_and_models_tcache_diversion() -> None:
    for version in matrix.SUPPORTED_VERSIONS:
        build = matrix.build_versioned_fastbin(
            action="dup", glibc_version=version, chunk_addr=0x55555000,
            chunk_size=0x70, peer_or_fake_addr=0x55555100,
        )
        constraints = json.loads(build.metadata["constraints"])
        profile = matrix.profile_for(version)
        assert (any("fill seven" in item for item in constraints)) is profile.tcache
        stored = int.from_bytes(build.slice("fastbin_chunk.fd"), "little")
        expected = 0x55555100 ^ ((0x55555010 >> 12) if profile.safe_linking else 0)
        assert stored == expected


def test_tcache_transition_key_and_safe_linking_are_version_correct() -> None:
    with pytest.raises(matrix.VersionMatrixError, match="no tcache"):
        matrix.build_versioned_tcache(
            action="dup", glibc_version="2.25", chunk_addr=0x55555000,
            chunk_size=0x90, peer_or_target_addr=0x55555100,
        )

    legacy = matrix.build_versioned_tcache(
        action="dup", glibc_version="2.26", chunk_addr=0x55555000,
        chunk_size=0x90, peer_or_target_addr=0x55555100,
    )
    assert "ordinary user data" in legacy.metadata["constraints"]
    keyed = matrix.build_versioned_tcache(
        action="dup", glibc_version="2.29", chunk_addr=0x55555000,
        chunk_size=0x90, peer_or_target_addr=0x55555100,
    )
    assert "key" in keyed.metadata["operations"]

    safe = matrix.build_versioned_tcache(
        action="poison", glibc_version="2.32", chunk_addr=0x55555000,
        chunk_size=0x90, peer_or_target_addr=0x404040,
    )
    slot = 0x55555010
    assert int.from_bytes(safe.slice("poisoned_tcache_entry.next"), "little") == 0x404040 ^ (slot >> 12)
    assert json.loads(safe.metadata["allocator_profile"])["safe_linking"] is True

    for minor in range(26, 40):
        build = matrix.build_versioned_tcache(
            action="poison", glibc_version=f"2.{minor}", chunk_addr=0x55555000,
            chunk_size=0x90, peer_or_target_addr=0x404040,
        )
        stored = int.from_bytes(build.slice("poisoned_tcache_entry.next"), "little")
        expected = 0x404040 ^ ((slot >> 12) if minor >= 32 else 0)
        assert stored == expected
        assert ("poisoned_tcache_entry.key" in build.placements) is (minor >= 29)


def test_fastbin_poison_branch_and_default_size_bounds() -> None:
    poisoned = matrix.build_versioned_fastbin(
        action="poison", glibc_version="2.39", chunk_addr=0x55555000,
        chunk_size=0x70, peer_or_fake_addr=0x404000,
    )
    assert "poisoned_fastbin_victim.fd" in poisoned.placements
    assert int.from_bytes(poisoned.slice("poisoned_fastbin_victim.fd"), "little") == (
        0x404000 ^ (0x55555010 >> 12)
    )
    with pytest.raises(matrix.VersionMatrixError, match="max_fast_chunk"):
        matrix.build_versioned_fastbin(
            action="dup", glibc_version="2.39", chunk_addr=0x55555000,
            chunk_size=0x90, peer_or_fake_addr=0x55555100,
        )
    with pytest.raises(matrix.VersionMatrixError, match="tcache range"):
        matrix.build_versioned_tcache(
            action="poison", glibc_version="2.39", chunk_addr=0x55555000,
            chunk_size=0x420, peer_or_target_addr=0x404040,
        )


def test_hook_endpoint_is_available_through_233_and_refused_from_234() -> None:
    for minor in range(23, 34):
        build = matrix.build_versioned_hook_overwrite(
            glibc_version=f"2.{minor}", hook_address=0x7FFFF7FAE8E8,
            replacement_address=0x7FFFF7E12340, hook="free",
        )
        assert struct.unpack("<Q", build.payload)[0] == 0x7FFFF7E12340
        assert build.base_address == 0x7FFFF7FAE8E8
    for minor in range(34, 40):
        with pytest.raises(matrix.VersionMatrixError, match="removed"):
            matrix.build_versioned_hook_overwrite(
                glibc_version=f"2.{minor}", hook_address=0x7FFFF7FAE8E8,
                replacement_address=0x7FFFF7E12340,
            )


def test_hook_overwrite_rejects_invalid_widths_and_crossing_target_ranges() -> None:
    for bits in (16, 128, True):
        with pytest.raises(matrix.VersionMatrixError, match="bits must be 32 or 64"):
            matrix.build_versioned_hook_overwrite(
                glibc_version="2.33", hook_address=0x1000,
                replacement_address=0x2000, bits=bits,
            )

    adjacent = matrix.build_versioned_hook_overwrite(
        glibc_version="2.33", hook_address=(1 << 32) - 4,
        replacement_address=0x12345678, bits=32,
    )
    assert adjacent.base_address + len(adjacent.payload) == 1 << 32
    assert adjacent.payload == bytes.fromhex("78563412")

    with pytest.raises(matrix.VersionMatrixError, match="target range crosses"):
        matrix.build_versioned_hook_overwrite(
            glibc_version="2.33", hook_address=(1 << 64) - 1,
            replacement_address=1, bits=64,
        )


def test_public_version_matrix_builders_have_complete_static_samples() -> None:
    samples = {
        "heap_version_matrix.build_allocator_profile_block":
            matrix.build_allocator_profile_block("2.39"),
        "heap_version_matrix.build_versioned_tcache":
            matrix.build_versioned_tcache(
                action="poison", glibc_version="2.39", chunk_addr=0x55555000,
                chunk_size=0x90, peer_or_target_addr=0x404040),
        "heap_version_matrix.build_versioned_fastbin":
            matrix.build_versioned_fastbin(
                action="dup", glibc_version="2.23", chunk_addr=0x55555000,
                chunk_size=0x70, peer_or_fake_addr=0x55555100),
        "heap_version_matrix.build_versioned_hook_overwrite":
            matrix.build_versioned_hook_overwrite(
                glibc_version="2.33", hook_address=0x7FFFF7FAE8E8,
                replacement_address=0x7FFFF7E12340),
    }
    manifest = verify.make_manifest((matrix,), samples)
    assert manifest.complete, manifest.missing


@pytest.mark.parametrize("bad", ["2.22", "2.40", "3.23", "latest", ""])
def test_version_matrix_rejects_out_of_scope_versions(bad: str) -> None:
    with pytest.raises(matrix.VersionMatrixError):
        matrix.profile_for(bad)
