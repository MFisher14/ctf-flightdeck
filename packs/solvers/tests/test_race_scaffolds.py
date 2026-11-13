"""Deterministic structural tests for inert r5b race scaffolds."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

from contract import PayloadBuild  # noqa: E402
import race_scaffolds as races  # noqa: E402


def assert_inert_plan(result: PayloadBuild, strategy: str) -> dict[str, bytes]:
    payload, placements = result
    assert payload == result.payload and placements == result.placements
    assert payload.startswith(races.MAGIC)
    assert result.strategy == strategy
    assert result.metadata["inert_source"] == "true"
    assert result.metadata["source_guard"] == "#error"
    assert all(placements[name] + result.widths[name] <= len(payload)
               for name in result.widths)
    sections = races.parse_sections(payload)
    assert sections["source.c"].startswith(b"#error ")
    assert b"main(" not in sections["source.c"]
    timeline = json.loads(sections["timeline"])
    assert [row["sequence"] for row in timeline] == list(range(len(timeline)))
    assert len({row["event"] for row in timeline}) == len(timeline)
    for name, data in sections.items():
        assert result.slice(f"section.{name}") == data
    return sections


def test_userfaultfd_missing_plan_maps_buffers_and_timeline_deterministically():
    kwargs = dict(
        kernel_version="6.6.12", fault_page_address=0x100000,
        initial_buffer=b"R5B_UFFD_CHECKED", replacement_buffer=b"R5B_UFFD_CHANGED",
        mode="missing", max_retries=32, timeout_ms=2500,
    )
    result = races.build_userfaultfd_race_plan(**kwargs)
    sections = assert_inert_plan(result, "userfaultfd-race-review")
    assert len(sections["buffer.initial"]) == 4096
    assert len(sections["buffer.replacement"]) == 4096
    assert sections["buffer.initial"].startswith(b"R5B_UFFD_CHECKED")
    assert sections["buffer.replacement"].startswith(b"R5B_UFFD_CHANGED")
    assert set(sections["buffer.initial"][len(b"R5B_UFFD_CHECKED"):]) == {0}
    assert set(sections["buffer.replacement"][len(b"R5B_UFFD_CHANGED"):]) == {0}
    manifest = json.loads(sections["manifest"])
    assert manifest["fault_page_address"] == "0x100000"
    assert manifest["buffer_length"] == len(b"R5B_UFFD_CHECKED")
    assert manifest["backing_length"] == 4096 and manifest["padding_byte"] == 0
    assert manifest["max_retries"] == 32 and manifest["timeout_ms"] == 2500
    events = [row["event"] for row in json.loads(sections["timeline"])]
    assert events == [
        "probe_features", "register_range", "wait_for_fault",
        "enter_checked_operation", "mutate_controlled_state", "resolve_fault",
        "join_and_verify",
    ]
    assert "CAP_SYS_PTRACE" in result.metadata["prerequisites_json"]
    assert result.metadata["logical_buffer_length"] == str(len(b"R5B_UFFD_CHECKED"))
    assert result.metadata["page_backing_length"] == "4096"
    assert result.payload == races.build_userfaultfd_race_plan(**kwargs).payload


def test_userfaultfd_writeprotect_prerequisites_and_guards():
    result = races.build_userfaultfd_race_plan(
        kernel_version="5.11", fault_page_address=0x200000,
        initial_buffer=b"AAAA", replacement_buffer=b"BBBB",
        mode="writeprotect", unprivileged=True, kernel_faults=False,
    )
    sections = assert_inert_plan(result, "userfaultfd-race-review")
    assert b"UFFDIO_WRITEPROTECT_remove" in sections["source.c"]
    assert "UFFD_USER_MODE_ONLY" in result.metadata["prerequisites_json"]
    with pytest.raises(races.RaceBuildError, match="5.7"):
        races.build_userfaultfd_race_plan(
            kernel_version="5.6", fault_page_address=0x200000,
            initial_buffer=b"AAAA", replacement_buffer=b"BBBB", mode="writeprotect",
        )
    with pytest.raises(races.RaceBuildError, match="page-aligned"):
        races.build_userfaultfd_race_plan(
            kernel_version="6.6", fault_page_address=0x200001,
            initial_buffer=b"AAAA", replacement_buffer=b"BBBB",
        )


def test_fuse_plan_has_private_mount_lifecycle_and_controlled_buffers():
    result = races.build_fuse_race_plan(
        kernel_version="6.6", mapped_buffer_address=0x300000,
        initial_buffer=b"R5B_FUSE_ONE", replacement_buffer=b"R5B_FUSE_TWO",
        mountpoint="/tmp/r5b-fuse-fixture", direct_io=True,
        max_retries=11, timeout_ms=1800,
    )
    sections = assert_inert_plan(result, "fuse-race-review")
    manifest = json.loads(sections["manifest"])
    assert manifest["mountpoint"] == "/tmp/r5b-fuse-fixture"
    assert manifest["direct_io"] is True
    assert sections["buffer.initial"] == b"R5B_FUSE_ONE"
    assert sections["buffer.replacement"] == b"R5B_FUSE_TWO"
    events = [row["event"] for row in json.loads(sections["timeline"])]
    assert events[0] == "mount_review_filesystem"
    assert events[-1] == "join_verify_unmount"
    assert "/dev/fuse" in result.metadata["prerequisites_json"]
    with pytest.raises(races.RaceBuildError, match="absolute"):
        races.build_fuse_race_plan(
            kernel_version="6.6", mapped_buffer_address=0x300000,
            initial_buffer=b"AAAA", replacement_buffer=b"BBBB", mountpoint="relative",
        )


def test_generic_toctou_plan_bounds_workers_retries_and_state_transition():
    result = races.build_toctou_race_plan(
        kernel_version="6.1.0", controlled_buffer_address=0x404000,
        checked_buffer=b"R5B_CHECK_STATE", used_buffer=b"R5B_USE___STATE",
        resource_label="fixture_object", max_retries=500,
        timeout_ms=900, worker_count=3,
    )
    sections = assert_inert_plan(result, "generic-toctou-review")
    assert sections["buffer.checked"] == b"R5B_CHECK_STATE"
    assert sections["buffer.used"] == b"R5B_USE___STATE"
    manifest = json.loads(sections["manifest"])
    assert manifest["resource_label"] == "fixture_object"
    assert manifest["worker_count"] == 3
    events = [row["event"] for row in json.loads(sections["timeline"])]
    assert events == [
        "reset_attempt", "present_checked_buffer", "wait_for_check_boundary",
        "publish_used_buffer", "enter_use_boundary", "join_and_classify",
    ]
    assert result.metadata["max_retries"] == "500"
    assert result.metadata["total_retry_budget_ms"] == "450000"


def test_generic_toctou_range_rejects_wrap_and_accepts_exact_address_space_end():
    exact = races.build_toctou_race_plan(
        kernel_version="6.6", controlled_buffer_address=(1 << 64) - 2,
        checked_buffer=b"AB", used_buffer=b"CD", max_retries=1, timeout_ms=1,
    )
    assert exact.metadata["buffer_address"] == "0xfffffffffffffffe"
    with pytest.raises(races.RaceBuildError, match="wraps the 64-bit address space"):
        races.build_toctou_race_plan(
            kernel_version="6.6", controlled_buffer_address=(1 << 64) - 1,
            checked_buffer=b"AB", used_buffer=b"CD", max_retries=1, timeout_ms=1,
        )


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda: races.build_toctou_race_plan(
            kernel_version="6.6", controlled_buffer_address=0x1000,
            checked_buffer=b"A", used_buffer=b"B", max_retries=0), "max_retries"),
        (lambda: races.build_toctou_race_plan(
            kernel_version="6.6", controlled_buffer_address=0x1000,
            checked_buffer=b"A", used_buffer=b"BB"), "equal-length"),
        (lambda: races.build_toctou_race_plan(
            kernel_version="6.6", controlled_buffer_address=0x1000,
            checked_buffer=b"A", used_buffer=b"B", worker_count=1), "worker_count"),
        (lambda: races.build_fuse_race_plan(
            kernel_version="2.6.13", mapped_buffer_address=0x1000,
            initial_buffer=b"A", replacement_buffer=b"B"), "2.6.14"),
        (lambda: races.build_userfaultfd_race_plan(
            kernel_version="4.2", fault_page_address=0x1000,
            initial_buffer=b"A", replacement_buffer=b"B"), "4.3"),
        (lambda: races.build_toctou_race_plan(
            kernel_version="6.6", controlled_buffer_address=0x1000,
            checked_buffer=b"A", used_buffer=b"B",
            max_retries=1000, timeout_ms=1000), "total budget"),
    ],
)
def test_race_scaffolds_fail_closed_on_unbounded_or_impossible_inputs(call, message):
    with pytest.raises(races.RaceBuildError, match=message):
        call()


def test_section_parser_rejects_corruption_without_running_source():
    result = races.build_toctou_race_plan(
        kernel_version="6.6", controlled_buffer_address=0x5000,
        checked_buffer=b"AAAA", used_buffer=b"BBBB",
    )
    with pytest.raises(races.RaceBuildError, match="not an r5b"):
        races.parse_sections(b"not-an-envelope")
    with pytest.raises(races.RaceBuildError):
        races.parse_sections(result.payload[:-1])
    corrupted = bytearray(result.payload)
    corrupted[8:10] = (99).to_bytes(2, "little")
    with pytest.raises(races.RaceBuildError, match="unsupported"):
        races.parse_sections(bytes(corrupted))
    oversized = bytearray(result.payload)
    record = result.placements["record.manifest"]
    oversized[record + 2:record + 6] = (races.MAX_BUFFER + 1).to_bytes(4, "little")
    with pytest.raises(races.RaceBuildError, match="bounded range"):
        races.parse_sections(bytes(oversized))
    with pytest.raises(races.RaceBuildError, match="trailing"):
        races.parse_sections(result.payload + b"\x00")

