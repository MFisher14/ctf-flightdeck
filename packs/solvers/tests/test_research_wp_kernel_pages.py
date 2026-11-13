"""Regression vectors for the offline modern kernel page-geometry helper."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import research_wp_kernel_pages as pages  # noqa: E402


VMEMMAP = 0xFFFFEA0000000000


def test_x86_4level_indices_match_manual_bit_field_vector() -> None:
    # Manual extraction of 0xffff888012345678:
    # PGD=0x111, folded P4D=0, PUD=0, PMD=0x91, PTE=0x145, off=0x678.
    result = pages.decompose_x86_64_va(0xFFFF888012345678, levels=4)
    assert (result.pgd, result.p4d, result.pud, result.pmd, result.pte, result.offset) == (
        0x111, 0, 0, 0x91, 0x145, 0x678,
    )
    assert result.p4d_folded is True
    assert result.canonical_bits == 48
    assert result.as_dict()["address_hex"] == "0xffff888012345678"


def test_x86_5level_indices_match_manual_bit_field_vector() -> None:
    # Manual 9-bit grouping of the canonical high-half LA57 address.
    result = pages.decompose_x86_64_va(0xFF0123456789ABCD, levels=5)
    assert (result.pgd, result.p4d, result.pud, result.pmd, result.pte, result.offset) == (
        0x101, 0x46, 0x115, 0x13C, 0x9A, 0xBCD,
    )
    assert result.p4d_folded is False
    assert result.canonical_bits == 57


@pytest.mark.parametrize(
    ("address", "levels"),
    [
        (0x0000800000000000, 4),  # bit 47 set without sign extension
        (0x0100000000000000, 5),  # bit 56 set without sign extension
        (-1, 4),
        (True, 4),
        (0, 3),
    ],
)
def test_x86_decomposition_rejects_noncanonical_or_unbounded_input(address, levels) -> None:
    with pytest.raises(pages.ResearchWPKernelError):
        pages.decompose_x86_64_va(address, levels=levels)


def test_pfn_struct_page_and_physical_conversions_use_exact_supplied_geometry() -> None:
    # Independent arithmetic: 0x12345*0x40=0x48d140 and 0x12345*0x1000=0x12345000.
    by_pfn = pages.page_from_pfn(
        0x12345, vmemmap_base=VMEMMAP, struct_page_size=0x40, page_shift=12
    )
    assert by_pfn.struct_page_address == 0xFFFFEA000048D140
    assert by_pfn.physical_page_base == 0x12345000
    assert by_pfn.physical_address == 0x12345000
    assert by_pfn.page_offset == 0

    by_descriptor = pages.page_from_struct_page(
        0xFFFFEA000048D140,
        vmemmap_base=VMEMMAP,
        struct_page_size=0x40,
        page_shift=12,
    )
    assert by_descriptor == by_pfn

    by_physical = pages.page_from_physical_address(
        0x12345ABC,
        vmemmap_base=VMEMMAP,
        struct_page_size=0x40,
        page_shift=12,
    )
    assert by_physical.pfn == 0x12345
    assert by_physical.struct_page_address == 0xFFFFEA000048D140
    assert by_physical.physical_page_base == 0x12345000
    assert by_physical.page_offset == 0xABC


def test_page_geometry_rejects_misalignment_and_overflow_without_stdlib_errors() -> None:
    bad_calls = (
        lambda: pages.page_from_struct_page(
            VMEMMAP + 1, vmemmap_base=VMEMMAP, struct_page_size=0x40
        ),
        lambda: pages.page_from_pfn(
            1, vmemmap_base=VMEMMAP + 1, struct_page_size=0x40
        ),
        lambda: pages.page_from_pfn(
            1 << 63, vmemmap_base=VMEMMAP, struct_page_size=0x40
        ),
        lambda: pages.page_from_physical_address(
            True, vmemmap_base=VMEMMAP, struct_page_size=0x40
        ),
        lambda: pages.page_from_pfn(
            1, vmemmap_base=VMEMMAP, struct_page_size=0x40, page_shift=31
        ),
    )
    for call in bad_calls:
        with pytest.raises(pages.ResearchWPKernelError):
            call()


def test_pagejack_low_byte_classifies_redirect_and_fail_safe_without_exploit_claim() -> None:
    redirected = pages.classify_pagejack_low_byte(
        VMEMMAP + 0x40, vmemmap_base=VMEMMAP, struct_page_size=0x40
    )
    assert redirected.low_byte_before == 0x40
    assert redirected.zeroed_struct_page == VMEMMAP
    assert redirected.byte_delta == -0x40
    assert redirected.descriptor_delta == -1
    assert redirected.source_pfn == 1 and redirected.target_pfn == 0
    assert redirected.classification == "redirects-to-earlier-descriptor"
    assert redirected.arithmetically_feasible is True
    assert redirected.as_dict()["exploitability_verified"] is False

    unchanged = pages.classify_pagejack_low_byte(
        VMEMMAP + 0x100, vmemmap_base=VMEMMAP, struct_page_size=0x40
    )
    assert unchanged.descriptor_delta == 0
    assert unchanged.classification == "unchanged-low-byte-zero"
    assert unchanged.arithmetically_feasible is False

    below = pages.classify_pagejack_low_byte(
        0x10C0, vmemmap_base=0x10C0, struct_page_size=0x40
    )
    assert below.descriptor_delta == -3
    assert below.target_pfn is None
    assert below.classification == "below-vmemmap-base"
    assert below.arithmetically_feasible is False


def test_pagejack_requires_low_byte_result_to_be_a_descriptor_boundary() -> None:
    # pfn 3 at 96-byte stride is 0x120; clearing 0x20 is not a 96-byte step.
    with pytest.raises(pages.ResearchWPKernelError, match="boundary"):
        pages.classify_pagejack_low_byte(
            0x120, vmemmap_base=0, struct_page_size=96
        )


def test_cve_2025_37752_kmalloc_cg_192_published_landings() -> None:
    # Published write-up: https://syst3mfailure.io/two-bytes-of-madness/
    # The u16 zero write is 262636 (0x401ec) bytes beyond the SFQ Qdisc.
    first = pages.plan_slab_oob_landing(
        oob_delta=262636,
        source_offset=0,
        object_size=192,
        slab_pages=1,
        page_shift=12,
        write_width=2,
    )
    assert first.landing_offset == 0x1EC
    assert first.objects_per_slab == 21
    assert first.object_index == 2
    assert first.object_ordinal == 3
    assert first.offset_in_object == 108
    assert first.arithmetically_feasible is True

    second = pages.plan_slab_oob_landing(
        oob_delta=0x401EC,
        source_offset=0x800,
        object_size=192,
        slab_pages=1,
        page_shift=12,
        write_width=2,
    )
    assert second.landing_offset == 0x9EC
    assert second.object_index == 13
    assert second.object_ordinal == 14
    assert second.offset_in_object == 44
    assert second.arithmetically_feasible is True
    assert second.as_dict()["exploitability_verified"] is False


def test_slab_geometry_models_padding_redzones_and_bounds() -> None:
    padding = pages.plan_slab_oob_landing(
        oob_delta=4080,
        source_offset=0,
        object_size=192,
        slab_pages=1,
        write_width=2,
    )
    assert padding.landing_offset == 4080
    assert padding.hits_object is False
    assert padding.object_index is None
    assert padding.arithmetically_feasible is False

    redzone = pages.plan_slab_oob_landing(
        oob_delta=60,
        source_offset=0,
        object_size=48,
        object_stride=64,
        slab_pages=1,
        write_width=2,
    )
    assert redzone.slot_index == 0
    assert redzone.hits_object is False

    # A final object ending exactly at the slab boundary must be counted even
    # when stride is wider than the object itself.
    boundary = pages.plan_slab_oob_landing(
        oob_delta=64,
        source_offset=0,
        object_size=48,
        object_stride=64,
        first_object_offset=3984,
        slab_pages=1,
    )
    assert boundary.objects_per_slab == 2

    bad_calls = (
        lambda: pages.plan_slab_oob_landing(
            oob_delta=0, source_offset=0, object_size=192
        ),
        lambda: pages.plan_slab_oob_landing(
            oob_delta=1, source_offset=4096, object_size=192
        ),
        lambda: pages.plan_slab_oob_landing(
            oob_delta=1, source_offset=0, object_size=64, object_stride=32
        ),
        lambda: pages.plan_slab_oob_landing(
            oob_delta=1, source_offset=0, object_size=192, objects_per_slab=22
        ),
        lambda: pages.plan_slab_oob_landing(
            oob_delta=(1 << 64) - 1, source_offset=1, object_size=192
        ),
    )
    for call in bad_calls:
        with pytest.raises(pages.ResearchWPKernelError):
            call()


def test_guarded_cli_returns_systemexit_codes_and_deterministic_json(capsys) -> None:
    assert pages.main(["--help"]) == 0
    capsys.readouterr()
    assert pages.main([]) == 2
    capsys.readouterr()
    assert pages.main(["va", "not-an-integer"]) == 2
    capsys.readouterr()
    assert pages.main(42) == 2
    capsys.readouterr()

    assert pages.main([
        "slab",
        "--oob-delta", "0x401ec",
        "--source-offset", "0x800",
        "--object-size", "192",
        "--write-width", "2",
    ]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["object_index"] == 13
    assert report["object_ordinal"] == 14
    assert report["offset_in_object"] == 44
    assert captured.err == ""

