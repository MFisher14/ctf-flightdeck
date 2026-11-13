"""Published-vector tests for the offline page-geometry planner.

The constants below come from the Google kernelCTF exploit artifacts named in
each test.  Expected values are calculated directly from the documented Linux
formulas, never by another path through the engine under test.
"""
from __future__ import annotations

from collections.abc import Callable
import json

import pytest

import wpgap_pagegeo_planner as pagegeo


X86_4LEVEL = (("pte", 9), ("pmd", 9), ("pud", 9), ("pgd", 9))
PT_ARGS = {
    "levels": X86_4LEVEL,
    "page_shift": 12,
    "va_bits": 48,
    "word_bits": 64,
    "entry_size": 8,
    "canonical_policy": "sign-extended",
}

VMEMMAP = 0xFFFFEA0000000000
MEM_ARGS = {
    "memory_model": "sparsemem-vmemmap",
    "descriptor_base": VMEMMAP,
    "struct_page_size": 0x40,
    "page_shift": 12,
    "physical_address_bits": 52,
    "virtual_address_bits": 48,
    "word_bits": 64,
    "canonical_policy": "sign-extended",
    "valid_pfn_ranges": ((0, 0x100000),),
}


def _level_indices(result: object) -> dict[str, int]:
    rendered = result.as_dict()  # type: ignore[attr-defined]
    return {str(level["name"]): int(level["index"]) for level in rendered["levels"]}


def _field_landings(result: object) -> list[dict[str, object]]:
    rendered = result.as_dict()  # type: ignore[attr-defined]
    return list(rendered["field_landings"])


def test_cve_2024_1086_dirty_pagedirectory_published_va_relationships() -> None:
    """Oracle: kernelCTF CVE-2024-1086's published fixed mmap addresses."""

    # docs/exploit.md and src/exploit.c use these exact mappings.  Linux's
    # 4-level x86 shifts are PTE=12, PMD=21, PUD=30, PGD=39.
    vectors = {
        0x200000: {"pgd": 0, "pud": 0, "pmd": 1, "pte": 0},
        0x40000000: {"pgd": 0, "pud": 1, "pmd": 0, "pte": 0},
        0x8000000000: {"pgd": 1, "pud": 0, "pmd": 0, "pte": 0},
        0x8000200000: {"pgd": 1, "pud": 0, "pmd": 1, "pte": 0},
    }
    for address, expected in vectors.items():
        split = pagegeo.decompose_page_table(address, **PT_ARGS)
        assert _level_indices(split) == expected
        data = split.as_dict()
        assert data["offset"] == 0
        by_name = {row["name"]: row for row in data["levels"]}
        assert by_name["pte"]["shift"] == 12
        assert by_name["pmd"]["shift"] == 21
        assert by_name["pud"]["shift"] == 30
        assert by_name["pgd"]["shift"] == 39
        assert by_name["pmd"]["coverage_bytes"] == 0x200000
        assert by_name["pud"]["coverage_bytes"] == 0x40000000
        rebuilt = pagegeo.compose_page_table(expected, offset=0, **PT_ARGS)
        assert rebuilt.as_dict()["address"] == address

    kernel_half = _level_indices(
        pagegeo.decompose_page_table(0x8000000000, **PT_ARGS)
    )
    data_half = _level_indices(
        pagegeo.decompose_page_table(0x8000200000, **PT_ARGS)
    )
    assert (kernel_half["pgd"], kernel_half["pud"]) == (
        data_half["pgd"],
        data_half["pud"],
    )
    assert data_half["pmd"] - kernel_half["pmd"] == 1


def test_page_table_requires_declared_exact_geometry_and_canonical_input() -> None:
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.decompose_page_table(
            0x0000800000000000,  # bit 47 set without sign extension
            **PT_ARGS,
        )
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.decompose_page_table(
            0,
            levels=(("pte", 9), ("pmd", 9)),
            page_shift=12,
            va_bits=48,
            word_bits=64,
            entry_size=8,
            canonical_policy="sign-extended",
        )
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.decompose_page_table(0, **{**PT_ARGS, "canonical_policy": "lam"})


def test_page_table_folded_level_and_high_half_round_trip() -> None:
    address = 0xFFFF888012345678
    folded_args = {
        **PT_ARGS,
        "levels": (
            ("pte", 9),
            ("pmd", 9),
            ("pud", 9),
            ("p4d", 0),
            ("pgd", 9),
        ),
    }
    expected = {
        "pte": (address >> 12) & 0x1FF,
        "pmd": (address >> 21) & 0x1FF,
        "pud": (address >> 30) & 0x1FF,
        "p4d": 0,
        "pgd": (address >> 39) & 0x1FF,
    }
    split = pagegeo.decompose_page_table(address, **folded_args)
    assert _level_indices(split) == expected
    folded = next(row for row in split.as_dict()["levels"] if row["name"] == "p4d")
    assert folded["folded"] is True
    assert folded["coverage_bytes"] is None
    assert folded["leaf_alignment_pfns"] is None
    rebuilt = pagegeo.compose_page_table(
        expected, offset=address & 0xFFF, **folded_args
    )
    assert rebuilt.as_dict()["address"] == address


def test_linux_memory_model_pfn_descriptor_and_flatmem_math() -> None:
    pfn = 0x12345
    mapped = pagegeo.map_pfn(pfn, **MEM_ARGS)
    data = mapped.as_dict()
    # include/asm-generic/memory_model.h: vmemmap + pfn (C scales by
    # sizeof(struct page)); include/linux/pfn.h: PFN_PHYS(x) = x << shift.
    assert data["descriptor_address"] == VMEMMAP + pfn * 0x40
    assert data["physical_page_base"] == pfn * 0x1000
    assert pagegeo.map_descriptor(data["descriptor_address"], **MEM_ARGS).as_dict()[
        "pfn"
    ] == pfn

    flat_base = 0xFFFF888000100000
    arch_pfn_offset = 0x100
    flat = pagegeo.map_pfn(
        0x145,
        memory_model="flatmem",
        descriptor_base=flat_base,
        struct_page_size=0x38,
        page_shift=12,
        physical_address_bits=52,
        virtual_address_bits=48,
        word_bits=64,
        canonical_policy="sign-extended",
        valid_pfn_ranges=((0x100, 0x200),),
        arch_pfn_offset=arch_pfn_offset,
    )
    assert flat.as_dict()["descriptor_address"] == flat_base + 0x45 * 0x38
    assert pagegeo.map_descriptor(
        flat.as_dict()["descriptor_address"],
        memory_model="flatmem",
        descriptor_base=flat_base,
        struct_page_size=0x38,
        page_shift=12,
        physical_address_bits=52,
        virtual_address_bits=48,
        word_bits=64,
        canonical_policy="sign-extended",
        valid_pfn_ranges=((0x100, 0x200),),
        arch_pfn_offset=arch_pfn_offset,
    ).as_dict()["pfn"] == 0x145

    for unsupported in ("sparsemem", "unknown"):
        with pytest.raises(pagegeo.PageGeometryError):
            pagegeo.map_pfn(1, **{**MEM_ARGS, "memory_model": unsupported})
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.map_pfn(0x100000, **MEM_ARGS)  # end-exclusive validity bound


def test_memory_model_declines_missing_config_holes_and_ambiguous_options() -> None:
    with pytest.raises(pagegeo.PageGeometryError, match="arch_pfn_offset"):
        pagegeo.map_pfn(
            0x145,
            memory_model="flatmem",
            descriptor_base=0x100000,
            struct_page_size=0x38,
            page_shift=12,
            physical_address_bits=52,
            virtual_address_bits=48,
            word_bits=64,
            canonical_policy="sign-extended",
            valid_pfn_ranges=((0x100, 0x200),),
        )
    with pytest.raises(pagegeo.PageGeometryError, match="only valid"):
        pagegeo.map_pfn(1, **{**MEM_ARGS, "arch_pfn_offset": 0})
    with pytest.raises(pagegeo.PageGeometryError, match="outside"):
        pagegeo.map_pfn(
            0x180,
            **{**MEM_ARGS, "valid_pfn_ranges": ((0x100, 0x180), (0x200, 0x280))},
        )
    with pytest.raises(pagegeo.PageGeometryError, match="overlap"):
        pagegeo.map_pfn(
            0x100,
            **{**MEM_ARGS, "valid_pfn_ranges": ((0x100, 0x200), (0x180, 0x280))},
        )
    with pytest.raises(pagegeo.PageGeometryError, match="canonical"):
        pagegeo.map_pfn(
            1, **{**MEM_ARGS, "descriptor_base": 0x0000800000000000}
        )


def test_direct_map_is_bounded_affine_translation_not_an_arbitrary_va_cast() -> None:
    args = {
        "physical_base": 0x100000,
        "virtual_base": 0xFFFF888000000000,
        "length": 0x200000,
        "physical_address_bits": 52,
        "virtual_address_bits": 48,
        "word_bits": 64,
        "canonical_policy": "sign-extended",
    }
    physical = 0x123456
    virtual = 0xFFFF888000023456
    assert pagegeo.physical_to_direct_map(physical, **args).as_dict()[
        "virtual_address"
    ] == virtual
    assert pagegeo.direct_map_to_physical(virtual, **args).as_dict()[
        "physical_address"
    ] == physical
    by_pfn = pagegeo.pfn_to_direct_map(
        0x123, page_offset=0x456, page_shift=12, **args
    ).as_dict()
    assert by_pfn["physical_address"] == 0x123456
    assert by_pfn["virtual_address"] == virtual
    inverted = pagegeo.direct_map_to_pfn(
        virtual, page_shift=12, **args
    ).as_dict()
    assert (inverted["pfn"], inverted["page_offset"]) == (0x123, 0x456)
    last = args["physical_base"] + args["length"] - 1
    assert pagegeo.physical_to_direct_map(last, **args).as_dict()[
        "virtual_address"
    ] == args["virtual_base"] + args["length"] - 1
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.physical_to_direct_map(args["physical_base"] + args["length"], **args)
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.direct_map_to_physical(args["virtual_base"] - 1, **args)
    with pytest.raises(pagegeo.PageGeometryError, match="canonical"):
        pagegeo.physical_to_direct_map(
            0,
            **{
                **args,
                "physical_base": 0,
                "virtual_base": 0x0000800000000000,
            },
        )
    with pytest.raises(pagegeo.PageGeometryError, match="overflows"):
        pagegeo.physical_to_direct_map(
            (1 << 52) - 0x100,
            **{
                **args,
                "physical_base": (1 << 52) - 0x100,
                "length": 0x200,
            },
        )


def test_pagejack_published_adjacent_descriptor_low_byte_patch() -> None:
    """Oracle: PageJack's CVE-2022-0995 example sets bit 6, `00` -> `40`."""

    patch = pagegeo.plan_descriptor_pointer_patch(
        4,
        5,
        **MEM_ARGS,
        pointer_width=8,
        overwrite_offset=0,
        overwrite_width=1,
        byteorder="little",
    )
    data = patch.as_dict()
    assert data["source_pointer"] == VMEMMAP + 0x100
    assert data["target_pointer"] == VMEMMAP + 0x140
    assert data["descriptor_delta"] == 1
    assert data["patch_hex"] == "40"

    # A one-byte patch cannot change the next byte; preserved-byte mismatch is
    # rejected instead of producing a misleading patch.
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.plan_descriptor_pointer_patch(
            4,
            8,
            **MEM_ARGS,
            pointer_width=8,
            overwrite_offset=0,
            overwrite_width=1,
            byteorder="little",
        )

    # The overwrite offset is explicitly an in-memory byte position: the same
    # low-byte mutation occupies the last byte in a big-endian pointer.
    big = pagegeo.plan_descriptor_pointer_patch(
        4,
        5,
        **MEM_ARGS,
        pointer_width=8,
        overwrite_offset=7,
        overwrite_width=1,
        byteorder="big",
    )
    assert big.as_dict()["patch_hex"] == "40"


def _whole_page_file_landing(*, field_offset: int, field_width: int) -> object:
    return pagegeo.plan_page_uaf_landing(
        page_shift=12,
        physical_address_bits=52,
        released_head_pfn=0x23450,
        released_order=0,
        stale_page_index=0,
        stale_offset=0,
        stale_length=0x1000,
        replacement_head_pfn=0x23450,
        replacement_order=0,
        first_object_offset=0,
        object_stride=0x100,
        object_size=232,
        objects_per_slab=16,
        field_offset=field_offset,
        field_width=field_width,
    )


def test_cve_2024_0582_page_uaf_reclaimed_by_published_filp_layout() -> None:
    """Oracle: mitigation-v4 exploit's 4 KiB page and struct-file constants."""

    result = _whole_page_file_landing(field_offset=0xC8, field_width=8)
    data = result.as_dict()
    assert data["extent_relation"] == "exact"
    assert data["access_relation"] == "fully-contained-in-replacement"
    landings = _field_landings(result)
    assert [row["object_index"] for row in landings] == list(range(16))
    base = 0x23450 << 12
    assert [row["field_start"] - base for row in landings] == [
        slot * 0x100 + 0xC8 for slot in range(16)
    ]
    assert landings[-1]["field_start"] - base == 0xFC8
    assert all(row["fully_reachable"] is True for row in landings)


def test_cve_2025_37752_tmp_page_to_signalfd_file_field_geometry() -> None:
    """Oracle: published COS offsets f_cred=0x90, private_data=0xc8."""

    cred = _field_landings(_whole_page_file_landing(field_offset=0x90, field_width=8))
    private = _field_landings(
        _whole_page_file_landing(field_offset=0xC8, field_width=8)
    )
    assert len(cred) == len(private) == 16
    assert [p["field_start"] - c["field_start"] for c, p in zip(cred, private)] == [
        0x38
    ] * 16


def test_page_uaf_overlap_reports_partial_geometry_without_claiming_reuse() -> None:
    result = pagegeo.plan_page_uaf_landing(
        page_shift=12,
        physical_address_bits=52,
        released_head_pfn=0x300,
        released_order=2,
        stale_page_index=2,
        stale_offset=0x800,
        stale_length=0x1000,
        replacement_head_pfn=0x302,
        replacement_order=1,
        first_object_offset=0,
        object_stride=0x100,
        object_size=0xE8,
        objects_per_slab=32,
        field_offset=0x20,
        field_width=8,
    )
    data = result.as_dict()
    assert data["extent_relation"] == "replacement-within-released"
    assert data["access_relation"] == "fully-contained-in-replacement"
    assert data["reuse_guaranteed"] is False
    assert data["stale_source_page_indices"] == [2, 3]
    assert data["replacement_page_indices"] == [0, 1]
    assert data["warnings"]


def test_page_uaf_distinguishes_partial_field_from_full_reachability() -> None:
    result = pagegeo.plan_page_uaf_landing(
        page_shift=12,
        physical_address_bits=52,
        released_head_pfn=0x400,
        released_order=0,
        stale_page_index=0,
        stale_offset=0xC9,
        stale_length=4,
        replacement_head_pfn=0x400,
        replacement_order=0,
        first_object_offset=0,
        object_stride=0x100,
        object_size=0xE8,
        objects_per_slab=16,
        field_offset=0xC8,
        field_width=8,
    ).as_dict()
    assert result["reachable_fields"] == []
    assert len(result["partial_fields"]) == 1
    assert result["partial_fields"][0]["object_index"] == 0
    assert result["partial_fields"][0]["fully_reachable"] is False


def test_page_uaf_declines_unaligned_extent_and_unknown_or_crossing_layout() -> None:
    exact = {
        "page_shift": 12,
        "physical_address_bits": 52,
        "released_head_pfn": 0x300,
        "released_order": 2,
        "stale_page_index": 0,
        "stale_offset": 0,
        "stale_length": 0x1000,
        "replacement_head_pfn": 0x300,
        "replacement_order": 0,
        "first_object_offset": 0,
        "object_stride": 0x100,
        "object_size": 0xE8,
        "objects_per_slab": 16,
        "field_offset": 0x20,
        "field_width": 8,
    }
    with pytest.raises(pagegeo.PageGeometryError, match="aligned"):
        pagegeo.plan_page_uaf_landing(
            **{**exact, "released_head_pfn": 0x301}
        )
    with pytest.raises(pagegeo.PageGeometryError):
        pagegeo.plan_page_uaf_landing(**{**exact, "object_stride": 0})
    with pytest.raises(pagegeo.PageGeometryError, match="field exceeds"):
        pagegeo.plan_page_uaf_landing(
            **{**exact, "field_offset": 0xE4, "field_width": 8}
        )
    with pytest.raises(pagegeo.PageGeometryError, match="beyond"):
        pagegeo.plan_page_uaf_landing(
            **{**exact, "stale_page_index": 3, "stale_offset": 0x800,
               "stale_length": 0x1000}
        )


def test_public_apis_normalize_malformed_input_to_declared_error() -> None:
    malformed_calls: tuple[Callable[[], object], ...] = (
        lambda: pagegeo.decompose_page_table("0x200000", **PT_ARGS),
        lambda: pagegeo.decompose_page_table(0, **{**PT_ARGS, "levels": (("pte", object()),)}),
        lambda: pagegeo.compose_page_table(
            {"pte": True, "pmd": 0, "pud": 0, "pgd": 0}, offset=0, **PT_ARGS
        ),
        lambda: pagegeo.map_pfn(True, **MEM_ARGS),
        lambda: pagegeo.map_pfn(1, **{**MEM_ARGS, "valid_pfn_ranges": ((0, object()),)}),
        lambda: pagegeo.map_descriptor(VMEMMAP + 1, **MEM_ARGS),
        lambda: pagegeo.pfn_to_direct_map(
            object(),
            page_offset=0,
            page_shift=12,
            physical_base=0,
            virtual_base=0,
            length=0x1000,
            physical_address_bits=52,
            virtual_address_bits=48,
            word_bits=64,
            canonical_policy="zero-extended",
        ),
        lambda: pagegeo.plan_descriptor_pointer_patch(
            4,
            5,
            **MEM_ARGS,
            pointer_width=8,
            overwrite_offset=object(),
            overwrite_width=1,
            byteorder="little",
        ),
        lambda: pagegeo.plan_page_uaf_landing(
            page_shift=12,
            physical_address_bits=52,
            released_head_pfn=1,
            released_order=0,
            stale_page_index=0,
            stale_offset=0,
            stale_length=4096,
            replacement_head_pfn=1,
            replacement_order=0,
            first_object_offset=0,
            object_stride=object(),
            object_size=1,
            objects_per_slab=1,
            field_offset=0,
            field_width=1,
        ),
    )
    for call in malformed_calls:
        with pytest.raises(pagegeo.PageGeometryError):
            call()


def test_guarded_cli_converts_argparse_exit_to_integer_status() -> None:
    assert pagegeo.main([]) == 2
    assert pagegeo.main(["--definitely-not-a-command"]) == 2


def test_guarded_cli_emits_published_vector_json(capsys: pytest.CaptureFixture[str]) -> None:
    status = pagegeo.main(
        [
            "pt-decompose",
            "0x8000200000",
            "--level",
            "pte:9",
            "--level",
            "pmd:9",
            "--level",
            "pud:9",
            "--level",
            "pgd:9",
            "--page-shift",
            "12",
            "--va-bits",
            "48",
            "--word-bits",
            "64",
            "--entry-size",
            "8",
            "--canonical-policy",
            "sign-extended",
        ]
    )
    assert status == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["indices"] == {"pgd": 1, "pmd": 1, "pte": 0, "pud": 0}
