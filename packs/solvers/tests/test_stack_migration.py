"""Tests for static pivot discovery and explicit multi-stage wire splits."""
from pathlib import Path
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import stack_migration as migration  # noqa: E402
from contract import BuildError  # noqa: E402
from gadget_catalog import Gadget, GadgetCatalog  # noqa: E402


def _catalog():
    rows = (
        Gadget(0x401010, 0x10, "pop rdi ; ret", b"\x5f\xc3", 16),
        Gadget(0x401020, 0x20, "pop rsi ; ret", b"\x5e\xc3", 16),
        Gadget(0x401030, 0x30, "pop rdx ; ret", b"\x5a\xc3", 16),
        Gadget(0x401040, 0x40, "pop rsp ; ret", b"\x5c\xc3", 16),
        Gadget(0x401050, 0x50, "leave ; ret", b"\xc9\xc3", 16),
        Gadget(0x401060, 0x60, "xchg rax, rsp ; ret", b"\x48\x94\xc3", 8),
    )
    return GadgetCatalog("amd64", 64, "little", 2, 0x401000, rows)


def _elf64(code: bytes):
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    offset = 120
    address = 0x400000 + offset
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, address, 64, 0, 0, 64, 56, 1, 0, 0, 0
    )
    program = struct.pack("<IIQQQQQQ", 1, 5, offset, address, address, len(code), len(code), 0x1000)
    return header + program + code, address


def _word(build, label):
    return int.from_bytes(build.slice(label), "little")


def test_pivot_catalog_accepts_supplied_catalog_and_supplied_elf():
    result = migration.catalog_pivots(_catalog())
    assert [item.strategy for item in result.pivots] == [
        "pop-sp", "leave-ret", "exchange-sp"
    ]
    assert result.choose().address == 0x401040

    elf, base = _elf64(b"\x90\x5c\xc3\xc9\xc3")
    from_elf = migration.catalog_pivots(elf)
    assert from_elf.choose(("pop-sp",)).address == base + 1
    assert from_elf.find("leave-ret")[0].address == base + 3


@pytest.mark.parametrize("strategy,setup", [("pop-sp", None), ("exchange-sp", 0x401070), ("leave-ret", 0x401080)])
def test_each_pivot_contract_maps_new_stack(strategy, setup):
    pivot = migration.catalog_pivots(_catalog()).find(strategy)[0]
    build = migration.build_pivot_stage(
        pivot, new_stack_address=0x404800, overflow_offset=24,
        setup_gadget=setup, base_address=0x7FFFFFFFE000,
    )
    assert _word(build, "new_stack_address") == 0x404800
    assert _word(build, "pivot_gadget") == pivot.address
    assert build.metadata["pivot_semantic"] == pivot.semantic


def test_catalog_selected_stage_is_deterministic_and_requires_setup_when_needed():
    build = migration.build_catalog_pivot_stage(
        _catalog(), new_stack_address=0x404800,
        preferences=("pop-sp",), overflow_offset=8,
    )
    assert build.strategy == "catalog-selected-stack-migration"
    assert _word(build, "pivot_gadget") == 0x401040

    with pytest.raises(BuildError, match="requires a caller-supplied setup"):
        migration.build_catalog_pivot_stage(
            _catalog(), new_stack_address=0x404800,
            preferences=("exchange-sp",),
        )


def test_read_then_migrate_bundle_has_exact_stage_boundary_and_read_arguments():
    stage2 = b"R5B_STAGE_TWO\x00" + bytes(range(16))
    build = migration.build_read_then_migrate_amd64(
        _catalog(), read_address=0x401080, destination=0x404800,
        stage2=stage2, overflow_offset=40, stage1_base=0x7FFFFFFFE000,
    )
    assert _word(build, "read_rdi") == 0
    assert _word(build, "read_rsi") == 0x404800
    assert _word(build, "read_rdx") == len(stage2)
    assert _word(build, "read_address") == 0x401080
    assert _word(build, "pop_rsp") == 0x401040
    assert build.slice("stage2") == stage2
    assert build.placements["stage2"] == int(build.metadata["stage1_length"])


def test_leave_hop_bundle_encodes_separately_placed_fake_frames():
    hops = (
        migration.LeaveHop(0x404800, 0x404900, 0x401050),
        migration.LeaveHop(0x404900, 0x404A00, 0x401050),
        migration.LeaveHop(0x404A00, 0, 0x401100),
    )
    build = migration.build_leave_hop_bundle(hops)
    assert len(build.payload) == 3 * 16
    assert _word(build, "hop[0].next_frame_pointer") == 0x404900
    assert _word(build, "hop[2].continuation") == 0x401100
    assert build.metadata["frame_addresses"] == "0x404800,0x404900,0x404a00"


def test_migration_rejects_missing_catalog_gadgets_and_bad_bytes():
    empty = GadgetCatalog("amd64", 64, "little", 2, 0x401000, ())
    with pytest.raises(BuildError, match="lacks pop rdi"):
        migration.build_read_then_migrate_amd64(
            empty, read_address=1, destination=2, stage2=b"x", overflow_offset=0
        )
    with pytest.raises(BuildError, match="forbidden bytes"):
        migration.build_leave_hop_bundle(
            (migration.LeaveHop(0x1000, 0x4141414141414141, 2),), bad_bytes={0x41}
        )
    with pytest.raises(BuildError, match="must be unique"):
        migration.build_leave_hop_bundle((
            migration.LeaveHop(0x404800, 0x404800, 0x401050),
            migration.LeaveHop(0x404800, 0, 0x401100),
        ))
    with pytest.raises(BuildError, match="does not link"):
        migration.build_leave_hop_bundle((
            migration.LeaveHop(0x404800, 0x404A00, 0x401050),
            migration.LeaveHop(0x404900, 0, 0x401100),
        ))


@pytest.mark.parametrize("architecture", ["arm", "", True, None, ["amd64"]])
def test_manual_pivot_rejects_every_unsupported_architecture(architecture):
    pivot = migration.PivotGadget(
        0x401000, architecture, "pop-sp", "pop rsp ; ret", "rsp", "test contract"
    )
    with pytest.raises(BuildError, match="pivot architecture must be amd64 or i386"):
        migration.build_pivot_stage(pivot, new_stack_address=0x404800)


def test_manual_pivot_rejects_inconsistent_semantic_strategy_and_setup():
    mismatched = migration.PivotGadget(
        0x401000, "amd64", "pop-sp", "leave ; ret", "rbp", "test contract"
    )
    with pytest.raises(BuildError, match="strategy/setup does not match"):
        migration.build_pivot_stage(mismatched, new_stack_address=0x404800)

    wrong_abi_semantic = migration.PivotGadget(
        0x8049000, "i386", "pop-sp", "pop rsp ; ret", "rsp", "test contract"
    )
    with pytest.raises(BuildError, match="strategy/setup does not match"):
        migration.build_pivot_stage(wrong_abi_semantic, new_stack_address=0x804A000)


def test_pivot_catalog_rejects_load_bias_address_space_overflow():
    elf, _ = _elf64(b"\x5c\xc3")
    with pytest.raises(BuildError, match="does not fit in 64 bits"):
        migration.catalog_pivots(elf, load_bias=1 << 64)


def test_leave_hop_ranges_reject_overlap_but_allow_exact_adjacency():
    with pytest.raises(BuildError, match="frame ranges overlap"):
        migration.build_leave_hop_bundle((
            migration.LeaveHop(0x1000, 0x1008, 0x401050),
            migration.LeaveHop(0x1008, 0, 0x401100),
        ))

    adjacent = migration.build_leave_hop_bundle((
        migration.LeaveHop(0x1000, 0x1010, 0x401050),
        migration.LeaveHop(0x1010, 0, 0x401100),
    ))
    assert adjacent.metadata["frame_addresses"] == "0x1000,0x1010"


@pytest.mark.parametrize(
    "architecture,address,bits",
    [("amd64", (1 << 64) - 8, 64), ("i386", (1 << 32) - 4, 32)],
)
def test_leave_hop_frame_range_rejects_address_space_wrap(architecture, address, bits):
    with pytest.raises(BuildError, match=rf"exceeds the {bits}-bit address space"):
        migration.build_leave_hop_bundle(
            (migration.LeaveHop(address, 0, 1),), architecture=architecture
        )


def test_pivot_and_read_migration_reject_address_space_wrap():
    pivot = migration.catalog_pivots(_catalog()).find("pop-sp")[0]
    with pytest.raises(BuildError, match="pivot payload exceeds the 64-bit address space"):
        migration.build_pivot_stage(
            pivot, new_stack_address=0x404800, base_address=(1 << 64) - 8
        )
    with pytest.raises(BuildError, match="stage2 destination exceeds the 64-bit address space"):
        migration.build_read_then_migrate_amd64(
            _catalog(), read_address=0x401080, destination=(1 << 64) - 1,
            stage2=b"xx", overflow_offset=0,
        )
    with pytest.raises(BuildError, match="stage1 payload exceeds the 64-bit address space"):
        migration.build_read_then_migrate_amd64(
            _catalog(), read_address=0x401080, destination=0x404800,
            stage2=b"x", overflow_offset=0, stage1_base=(1 << 64) - 8,
        )

