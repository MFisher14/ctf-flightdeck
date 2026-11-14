"""Fixed offline structural Docker round-trip for every heap-delta builder."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

from contract import PayloadBuild  # noqa: E402
import file_exploitation as filex  # noqa: E402
import heap_primitives as primitives  # noqa: E402
import heap_version_matrix as matrix  # noqa: E402
import pwn_verify as verify  # noqa: E402


VTABLE_START = 0x7FFFF7FA0000
VTABLE_END = 0x7FFFF7FA4000
VALID_WFILE = 0x7FFFF7FA10C0
VERIFY = os.environ.get("CTF_R5B_DOCKER_VERIFY") == "1"


def _samples() -> dict[str, PayloadBuild]:
    return {
        "heap_version_matrix.build_allocator_profile_block":
            matrix.build_allocator_profile_block("2.39"),
        "heap_version_matrix.build_versioned_tcache": matrix.build_versioned_tcache(
            action="poison", glibc_version="2.39", chunk_addr=0x55555000,
            chunk_size=0x90, peer_or_target_addr=0x404040),
        "heap_version_matrix.build_versioned_fastbin": matrix.build_versioned_fastbin(
            action="dup", glibc_version="2.23", chunk_addr=0x55555000,
            chunk_size=0x70, peer_or_fake_addr=0x55555100),
        "heap_version_matrix.build_versioned_hook_overwrite":
            matrix.build_versioned_hook_overwrite(
                glibc_version="2.33", hook_address=0x7FFFF7FAE8E8,
                replacement_address=0x7FFFF7E12340),
        "heap_primitives.build_heap_groom_plan": primitives.build_heap_groom_plan(
            chunk_size=0x90, live_chunks=5, holes=2, guard_chunks=1),
        "heap_primitives.build_uaf_reuse": primitives.build_uaf_reuse(
            glibc_version="2.35", freed_chunk_addr=0x55555000,
            chunk_size=0x90, replacement_addr=0x404040),
        "heap_primitives.build_double_free": primitives.build_double_free(
            glibc_version="2.31", chunk_addr=0x55555100,
            guard_or_next_addr=0x55555200, chunk_size=0x90),
        "heap_primitives.build_type_confusion": primitives.build_type_confusion(
            object_addr=0x404800, type_tag=3, data_pointer=0x404900,
            logical_length=0x80, call_pointer=0x401176),
        "heap_primitives.build_off_by_one": primitives.build_off_by_one(
            buffer_addr=0x55556000, overwrite_offset=0x40, replacement_byte=0x90),
        "heap_primitives.build_null_byte_poison": primitives.build_null_byte_poison(
            buffer_addr=0x55557000, victim_size_field_addr=0x55557040,
            original_size=0x191),
        "heap_primitives.build_integer_overflow_heap":
            primitives.build_integer_overflow_heap(
                header_addr=0x404A00, count=0x40000001, element_size=4,
                copy_count=16, integer_bits=32),
        "heap_primitives.build_cpp_vtable": primitives.build_cpp_vtable(
            object_addr=0x404B00, fake_vtable_addr=0x404C00,
            call_targets=(0x401176, 0x401200), original_fields=b"STATE123"),
        "file_exploitation.build_io_file_plus": filex.build_io_file_plus(
            glibc_version="2.37", file_addr=0x404800, vtable_addr=VALID_WFILE,
            lock_addr=0x404A00, vtable_section_start=VTABLE_START,
            vtable_section_end=VTABLE_END, wide_data_addr=0x404900),
        "file_exploitation.build_io_vtable_precondition":
            filex.build_io_vtable_precondition(
                glibc_version="2.23", file_addr=0x404800,
                fake_vtable_addr=0x404B00, call_target=0x401176,
                lock_addr=0x404A00),
        "file_exploitation.build_io_str_jumps": filex.build_io_str_jumps(
            glibc_version="2.27", file_addr=0x404800,
            io_str_jumps_addr=0x7FFFF7FA1800, allocate_callback=0x7FFFF7E12340,
            desired_callback_argument=0x1000, lock_addr=0x404A00,
            vtable_section_start=VTABLE_START, vtable_section_end=VTABLE_END),
        "file_exploitation.build_io_wide_variant": filex.build_io_wide_variant(
            variant="doallocate", glibc_version="2.39", file_addr=0x404800,
            wide_data_addr=0x404900, wide_vtable_addr=0x404A00,
            validated_main_vtable_addr=VALID_WFILE, call_target=0x401176,
            lock_addr=0x404B00, vtable_section_start=VTABLE_START,
            vtable_section_end=VTABLE_END),
    }


def _aggregate(samples: dict[str, PayloadBuild]) -> PayloadBuild:
    payload = bytearray()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    for sample_name, build in sorted(samples.items()):
        padding = (-len(payload)) % 8
        payload.extend(bytes(padding))
        start = len(payload)
        payload.extend(build.payload)
        placements[f"{sample_name}:payload"] = start
        widths[f"{sample_name}:payload"] = len(build.payload)
        for label, offset in build.placements.items():
            qualified = f"{sample_name}:{label}"
            placements[qualified] = start + offset
            if label in build.widths:
                widths[qualified] = build.widths[label]
    return PayloadBuild(
        payload=bytes(payload), placements=placements, widths=widths,
        architecture="r5b-heap-delta-bundle", strategy="all-builder-structural-roundtrip",
        metadata={"builder_count": str(len(samples)), "delivery": "none"},
    )


def test_static_manifest_and_aggregate_cover_every_public_delta_builder() -> None:
    samples = _samples()
    manifest = verify.make_manifest((matrix, primitives, filex), samples)
    assert manifest.complete, manifest.missing
    aggregate = _aggregate(samples)
    record = verify.verify_payload("heap-delta-aggregate", aggregate)
    assert record.length == len(aggregate.payload)
    assert record.placement_count > len(samples)


@pytest.mark.skipif(
    not VERIFY,
    reason="set CTF_R5B_DOCKER_VERIFY=1 for --pull=never --network none verification",
)
def test_all_delta_builders_roundtrip_in_fixed_sacrificial_container() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker CLI unavailable")
    inspected = subprocess.run(
        [docker, "image", "inspect", verify.DOCKER_IMAGE],
        capture_output=True, text=True, check=False,
    )
    if inspected.returncode:
        pytest.skip(f"prebuilt image unavailable: {verify.DOCKER_IMAGE}")
    samples = _samples()
    marker = f"R5B_HEAP_DELTA_ROUNDTRIP_OK:{len(samples)}\n".encode()
    record = verify.run_sacrificial_roundtrip(_aggregate(samples), marker=marker)
    assert record.evidence == "container-static-roundtrip"
    assert record.marker_sha256
