"""Non-circular tests for the pwnkern Linux heap primitive planners."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import pwnkern_linux_heap as linux  # noqa: E402


def test_msg_msg_matches_manual_upstream_x86_64_layout():
    values = (
        0xFFFF888000001000,
        0xFFFF888000002000,
        7,
        0x1234,
        0xFFFF888000003000,
        0,
    )
    result = linux.serialize_msg_msg(
        m_list_next=values[0],
        m_list_prev=values[1],
        m_type=values[2],
        m_ts=values[3],
        next_segment=values[4],
        security=values[5],
        text=b"KNOWN-TEXT",
    )
    # Independent reference: upstream field order is list_head(2 pointers),
    # long m_type, size_t m_ts, msg_msgseg *, security * on x86-64.
    expected = b"".join(value.to_bytes(8, "little") for value in values)
    expected += b"KNOWN-TEXT"
    assert result.payload == expected
    assert result.profile == "linux-x86_64-msg_msg-common-v1"
    assert [(item.name, item.offset, item.width) for item in result.placements] == [
        ("m_list.next", 0x00, 8),
        ("m_list.prev", 0x08, 8),
        ("m_type", 0x10, 8),
        ("m_ts", 0x18, 8),
        ("next", 0x20, 8),
        ("security", 0x28, 8),
        ("text", 0x30, 10),
    ]
    assert json.loads(json.dumps(result.as_dict()))["payload_hex"] == expected.hex()


def test_msg_msgseg_matches_manual_pointer_plus_text_layout():
    pointer = 0xFFFF8880ABCDF000
    result = linux.serialize_msg_msgseg(next_segment=pointer, text=b"SEG")
    assert result.payload == pointer.to_bytes(8, "little") + b"SEG"
    assert result.placements[1].offset == 8


def test_msg_allocation_spans_follow_published_page_minus_header_formula():
    # PAGE_SIZE 4096: first capacity 4096-48=4048, segment capacity 4096-8=4088.
    plan = linux.plan_msg_allocations(4048 + 4088 + 17)
    assert plan.first_capacity == 4048
    assert plan.segment_capacity == 4088
    assert [(s.payload_offset, s.payload_length, s.allocation_size) for s in plan.spans] == [
        (0, 4048, 4096),
        (4048, 4088, 4096),
        (8136, 17, 25),
    ]
    assert plan.total_allocation_bytes == 4096 + 4096 + 25
    empty = linux.plan_msg_allocations(0)
    assert len(empty.spans) == 1
    assert empty.spans[0].allocation_size == 48


def test_cross_cache_counts_are_hand_arithmetic_and_never_claim_certainty():
    plan = linux.plan_cross_cache(
        source_object_size=256,
        target_object_size=64,
        source_objects_per_slab=16,
        target_objects_per_slab=64,
        per_cpu_partial_slabs=2,
        release_slabs=3,
        reclaim_slabs=4,
        safety_slabs=1,
        allocator_profile="slub-typed",
    )
    assert plan.slab_bytes == 4096
    assert plan.source_count_is_estimate is False
    assert plan.target_count_is_estimate is False
    assert [phase.object_count for phase in plan.phases] == [48, 64, 1, 48, 256]
    rendered = " ".join(plan.warnings).lower()
    assert "cannot guarantee" in rendered
    assert "typed" in rendered


def test_cross_cache_derived_counts_use_only_explicit_alignment_formula():
    plan = linux.plan_cross_cache(
        source_object_size=33,
        target_object_size=100,
        object_alignment=16,
        release_slabs=1,
        reclaim_slabs=1,
        safety_slabs=0,
    )
    assert plan.source_objects_per_slab == 4096 // 48
    assert plan.target_objects_per_slab == 4096 // 112
    assert plan.source_count_is_estimate and plan.target_count_is_estimate
    assert any("estimate" in warning for warning in plan.warnings)


@pytest.mark.parametrize("variant", ["file", "cred"])
@pytest.mark.parametrize("blocker", ["userfaultfd", "fuse", "filesystem-lock"])
def test_dirtycred_timeline_contains_check_block_free_reclaim_resume(variant, blocker):
    plan = linux.plan_dirtycred(
        variant=variant,
        blocking_mechanism=blocker,
        free_primitive="double-free",
    )
    assert [phase.index for phase in plan.phases] == list(range(1, 7))
    timeline = " ".join(
        phase.name + " " + phase.detail for phase in plan.phases
    ).lower()
    assert "block" in timeline
    assert "free" in timeline
    assert "reclaim" in timeline
    assert "resume" in timeline
    assert any(blocker.split("-")[0] in item.lower() for item in plan.prerequisites)


def test_usma_pg_vec_matches_manual_qword_vector_and_exact_coverage():
    pointers = [0xFFFFFFFF81000000, 0xFFFFFFFF81200000]
    result = linux.build_usma_pg_vec(
        pointers,
        block_count=2,
        block_size=0x2000,
        mapping_length=0x4000,
        page_size=0x1000,
        access_path="existing-cap-net-raw",
    )
    expected = struct.pack("<Q", pointers[0]) + struct.pack("<Q", pointers[1])
    assert result.payload == expected
    assert result.pages_per_block == 2
    assert result.mapping_pages == 4
    assert result.mapping_length == 0x4000
    assert any("CAP_NET_RAW" in item for item in result.prerequisites)
    assert result.as_dict()["payload_hex"] == expected.hex()


@pytest.mark.parametrize(
    ("function", "args", "kwargs"),
    [
        (linux.serialize_msg_msg, (), {
            "m_list_next": "bad", "m_list_prev": 0, "m_type": 1,
            "m_ts": 1, "next_segment": 0, "security": 0,
        }),
        (linux.serialize_msg_msgseg, (), {"next_segment": 1, "text": object()}),
        (linux.plan_msg_allocations, (None,), {}),
        (linux.plan_msg_allocations, (-1,), {}),
        (linux.plan_cross_cache, (), {"source_object_size": [], "target_object_size": 64}),
        (linux.plan_cross_cache, (), {"source_object_size": 64, "target_object_size": 64, "object_alignment": 3}),
        (linux.plan_cross_cache, (), {"source_object_size": 64, "target_object_size": 64, "source_objects_per_slab": "x"}),
        (linux.plan_cross_cache, (), {"source_object_size": 256, "target_object_size": 64, "source_objects_per_slab": 17}),
        (linux.plan_dirtycred, (), {"variant": "other", "blocking_mechanism": "fuse", "free_primitive": "uaf-free"}),
        (linux.build_usma_pg_vec, (b"not-a-sequence",), {"block_count": 1, "block_size": 4096, "mapping_length": 4096}),
        (linux.build_usma_pg_vec, ([0xFFFFFFFF81000001],), {"block_count": 1, "block_size": 4096, "mapping_length": 4096}),
        (linux.build_usma_pg_vec, ([0xFFFFFFFF81000000],), {"block_count": 2, "block_size": 4096, "mapping_length": 8192}),
        (linux.build_usma_pg_vec, ([0xFFFFFFFF81000000],), {"block_count": 1, "block_size": 4096, "mapping_length": 8192}),
    ],
)
def test_every_malformed_public_builder_input_raises_only_declared_error(function, args, kwargs):
    with pytest.raises(linux.PwnkernLinuxError):
        function(*args, **kwargs)


def test_guarded_cli_help_error_and_json_hex(capsys):
    assert linux.main(["--help"]) == 0
    capsys.readouterr()
    assert linux.main(["msg-spans", "not-an-int"]) == 2
    error = capsys.readouterr().err
    assert "invalid integer" in error

    code = linux.main([
        "usma",
        "0xffffffff81000000",
        "--block-count", "1",
        "--block-size", "0x1000",
        "--mapping-length", "0x1000",
    ])
    assert code == 0
    document = json.loads(capsys.readouterr().out)
    assert document["payload_hex"] == struct.pack("<Q", 0xFFFFFFFF81000000).hex()
    assert document["mapping_pages"] == 1


def test_guarded_cli_catches_builder_validation_without_traceback(capsys):
    code = linux.main([
        "usma",
        "0xffffffff81000001",
        "--block-count", "1",
        "--block-size", "0x1000",
        "--mapping-length", "0x1000",
    ])
    assert code == 2
    captured = capsys.readouterr()
    assert "page-aligned" in captured.err
    assert "Traceback" not in captured.err


def test_guarded_cli_rejects_non_sequence_argv_without_leaking_typeerror(capsys):
    assert linux.main(42) == 2
    captured = capsys.readouterr()
    assert "malformed argv" in captured.err
    assert "Traceback" not in captured.err
