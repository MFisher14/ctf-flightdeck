"""Structural tests for deep rtld/link_map/REL(A)/RELR serializers."""
from pathlib import Path
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import dl_runtime as dl  # noqa: E402
from contract import BuildError  # noqa: E402


LAYOUT = dl.LinkMapLayout(
    size=0x300, l_addr=0x00, l_name=0x08, l_ld=0x10,
    l_next=0x18, l_prev=0x20, l_info=0x40,
    pointer_size=8, info_slots=32,
)

LAYOUT32 = dl.LinkMapLayout(
    size=0xC0, l_addr=0x00, l_name=0x04, l_ld=0x08,
    l_next=0x0C, l_prev=0x10, l_info=0x20,
    pointer_size=4, info_slots=32,
)


def _word(build, label, endian="little"):
    return int.from_bytes(build.slice(label), endian)


def test_dynamic_vector_serializes_signed_tags_values_and_null_terminator():
    build = dl.build_dynamic_vector(
        ((dl.DT_STRTAB, 0x500100), (dl.DT_SYMTAB, 0x500200)),
        base_address=0x500000,
    )
    assert len(build.payload) == 3 * 16
    assert _word(build, "dyn[0].tag") == dl.DT_STRTAB
    assert _word(build, "dyn[1].value") == 0x500200
    assert build.slice("dyn[null]") == b"\x00" * 16
    assert build.absolute_placements()["dyn[1]"] == 0x500010


@pytest.mark.parametrize(
    "architecture,rela,size",
    [("amd64", True, 24), ("amd64", False, 16), ("i386", True, 12), ("i386", False, 8)],
)
def test_rel_and_rela_records_pack_symbol_type_and_signed_addend(architecture, rela, size):
    build = dl.build_relocation_table(
        (dl.RelocationSpec(0x601018, 0x123, 7, -4),),
        architecture=architecture, rela=rela,
    )
    assert len(build.payload) == size
    info = _word(build, "rel[0].info")
    if architecture == "amd64":
        assert info == (0x123 << 32) | 7
    else:
        assert info == (0x123 << 8) | 7
    if rela:
        assert int.from_bytes(build.slice("rel[0].addend"), "little", signed=True) == -4


def _decode_relr(payload, bits=64):
    word = bits // 8
    entries = [int.from_bytes(payload[index:index + word], "little")
               for index in range(0, len(payload), word)]
    output, where = [], 0
    for entry in entries:
        if entry & 1 == 0:
            output.append(entry)
            where = entry + word
        else:
            for bit in range(1, bits):
                if entry & (1 << bit):
                    output.append(where + (bit - 1) * word)
            where += (bits - 1) * word
    return output


def test_relr_bitmap_round_trip_covers_sparse_and_dense_addresses():
    addresses = (0x600000, 0x600008, 0x600018, 0x600100, 0x601000)
    build = dl.build_relr_table(addresses)
    assert _decode_relr(build.payload) == list(addresses)
    assert int(build.metadata["entry_count"]) < len(addresses)


def test_caller_supplied_link_map_layout_maps_scalars_l_info_and_extra_state():
    build = dl.build_link_map_image(
        LAYOUT,
        base_address=0x500000,
        l_addr=0,
        l_name=0x500400,
        l_ld=0x500300,
        l_info={dl.DT_STRTAB: 0x500320, dl.DT_SYMTAB: 0x500330},
        extra_fields={"scope": (0x180, 0x500500)},
    )
    assert len(build.payload) == LAYOUT.size
    assert _word(build, "l_name") == 0x500400
    assert build.placements[f"l_info[{dl.DT_STRTAB}]"] == LAYOUT.l_info + dl.DT_STRTAB * 8
    assert _word(build, "extra.scope") == 0x500500
    assert build.metadata["private_layout"] == "caller-supplied"


def test_direct_runtime_resolver_stack_records_selector_units_per_abi():
    amd64 = dl.build_dl_runtime_resolve_stack(
        architecture="amd64", resolver_entry=0x7FFFF7FE0000,
        link_map=0x500000, relocation_selector=3,
        return_address=0x401000, arguments=(0x601000,), overflow_offset=24,
    )
    assert _word(amd64, "relocation_selector") == 3
    assert amd64.metadata["selector_units"] == "rela-index"
    i386 = dl.build_dl_runtime_resolve_stack(
        architecture="i386", resolver_entry=0xF7FE0000,
        link_map=0x8050000, relocation_selector=0x18,
        return_address=0x8049000,
    )
    assert _word(i386, "relocation_selector") == 0x18
    assert i386.metadata["selector_units"] == "rel-byte-offset"


def test_deep_dl_fixup_bundle_cross_links_link_map_dynamic_tables_symbol_and_rela():
    image = 0x500000
    build = dl.build_dl_fixup_bundle(
        LAYOUT,
        architecture="amd64",
        image_address=image,
        l_addr=0,
        symbol_name=b"system",
        relocation_target=0x601018,
        relocation_type=7,
        glibc_version="2.39",
        extra_link_map_fields={"scope": (0x180, 0x500900)},
    )
    assert build.slice("symbol_name") == b"system"
    assert build.payload[build.placements["symbol_name"] - 1] == 0
    assert _word(build, "link_map.l_ld") == build.absolute_placements()["dynamic"]
    str_dyn_pointer = _word(build, f"link_map.l_info[{dl.DT_STRTAB}]")
    assert str_dyn_pointer == build.absolute_placements()["dynamic.dyn[0]"]
    r_offset, r_info, addend = struct.unpack("<QQq", build.slice("fake_relocation"))
    assert r_offset == 0x601018 and r_info == (1 << 32) | 7 and addend == 0
    st_name, st_info, _other, _shndx, st_value, st_size = struct.unpack(
        "<IBBHQQ", build.slice("fake_symbol")
    )
    assert (st_name, st_info, st_value, st_size) == (1, 0x12, 0, 0)
    assert build.metadata["remaining_state"].startswith("scope/namespace")


def test_loader_builders_reject_private_layout_overruns_bad_relr_and_pointer_mismatch():
    bad_layout = dl.LinkMapLayout(0x40, 0, 8, 16, 24, 32, 0x30, 8, 8)
    with pytest.raises(BuildError, match="l_info vector exceeds"):
        dl.build_link_map_image(
            bad_layout, base_address=0, l_addr=0, l_name=0, l_ld=0
        )
    overlap_layout = dl.LinkMapLayout(0x200, 0, 0, 16, 24, 32, 0x40, 8, 16)
    with pytest.raises(BuildError, match="fields overlap"):
        dl.build_link_map_image(
            overlap_layout, base_address=0, l_addr=0, l_name=0, l_ld=0
        )
    with pytest.raises(BuildError, match="fields overlap"):
        dl.build_link_map_image(
            LAYOUT, base_address=0, l_addr=0, l_name=0, l_ld=0,
            extra_fields={"collision": (LAYOUT.l_addr, 1)},
        )
    with pytest.raises(BuildError, match="overlaps reserved l_info vector"):
        dl.build_link_map_image(
            LAYOUT, base_address=0, l_addr=0, l_name=0, l_ld=0,
            extra_fields={"collision": (LAYOUT.l_info + 31 * 8, 1)},
        )
    with pytest.raises(BuildError, match="word aligned"):
        dl.build_relr_table((0x600001,))
    with pytest.raises(BuildError, match="pointer size does not match"):
        dl.build_dl_fixup_bundle(
            dl.LinkMapLayout(0x200, 0, 4, 8, 12, 16, 0x20, 4, 32),
            architecture="amd64", image_address=0x500000, l_addr=0,
            symbol_name=b"system", relocation_target=0x601000,
            relocation_type=7, glibc_version="2.39",
        )


def test_standalone_loader_images_accept_exact_32bit_end_and_reject_wrap():
    limit = 1 << 32
    cases = (
        (
            "dynamic vector",
            lambda base: dl.build_dynamic_vector(
                ((dl.DT_STRTAB, 0x1000),), bits=32, base_address=base
            ),
        ),
        (
            "relocation table",
            lambda base: dl.build_relocation_table(
                (dl.RelocationSpec(0x1000, 1, 7),), architecture="i386",
                rela=False, base_address=base,
            ),
        ),
        (
            "RELR table",
            lambda base: dl.build_relr_table(
                (0x1000,), bits=32, base_address=base
            ),
        ),
        (
            "link_map image",
            lambda base: dl.build_link_map_image(
                LAYOUT32, base_address=base, l_addr=0, l_name=0, l_ld=0
            ),
        ),
    )
    for name, builder in cases:
        prototype = builder(0)
        exact = builder(limit - len(prototype.payload))
        assert exact.base_address + len(exact.payload) == limit
        with pytest.raises(BuildError, match=rf"{name} exceeds the 32-bit address space"):
            builder(limit - len(prototype.payload) + 1)


def test_dl_fixup_image_accepts_exact_32bit_end_and_rejects_wrap():
    kwargs = {
        "architecture": "i386",
        "l_addr": 0,
        "symbol_name": b"system",
        "relocation_target": 0x804A000,
        "relocation_type": 7,
        "glibc_version": "2.39",
    }
    prototype = dl.build_dl_fixup_bundle(LAYOUT32, image_address=0, **kwargs)
    exact_address = (1 << 32) - len(prototype.payload)
    exact = dl.build_dl_fixup_bundle(LAYOUT32, image_address=exact_address, **kwargs)
    assert exact.base_address + len(exact.payload) == 1 << 32
    with pytest.raises(BuildError, match="dl-fixup image exceeds the 32-bit address space"):
        dl.build_dl_fixup_bundle(LAYOUT32, image_address=exact_address + 1, **kwargs)


def test_dynamic_vector_rejects_empty_unterminated_shape():
    with pytest.raises(BuildError, match="cannot be empty without a terminator"):
        dl.build_dynamic_vector((), terminate=False)

