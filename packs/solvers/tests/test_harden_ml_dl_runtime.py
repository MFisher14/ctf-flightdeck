"""ELF byte builders only: no emitted image is loaded or executed.

Independent oracles: ELF gABI structs and hand-written RELR decoder.
https://gabi.xinuos.com/elf/06-reloc.html
https://gabi.xinuos.com/elf/08-dynamic.html
"""
import dataclasses
import random
import socket
import struct
import subprocess

import pytest
from elftools.elf.structs import ELFStructs
import dl_runtime as engine


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("an ELF byte builder attempted execution or network")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def _layout(bits=64):
    word = bits // 8
    return engine.LinkMapLayout(size=40 * word, l_addr=0, l_name=word, l_ld=2 * word,
                                l_next=3 * word, l_prev=4 * word, l_info=5 * word,
                                pointer_size=word, info_slots=24)


def _elfstructs(bits, little=True):
    obj = ELFStructs(little_endian=little, elfclass=bits)
    obj.create_basic_structs()
    obj.create_advanced_structs(e_type="ET_DYN", e_machine="EM_X86_64" if bits == 64 else "EM_386")
    return obj


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_dynamic_vector_elf_abi(bits, endian):
    build = engine.build_dynamic_vector([(5, 0x1234), (10, 9)], bits=bits, endian=endian)
    code = ("<" if endian == "little" else ">") + ("iI" if bits == 32 else "qQ")
    assert build.payload == b"".join(struct.pack(code, *pair) for pair in [(5, 0x1234), (10, 9), (0, 0)])
    parsed = _elfstructs(bits, endian == "little").Elf_Dyn.parse(build.payload)
    assert parsed.d_tag == "DT_STRTAB" and parsed.d_val == 0x1234


@pytest.mark.parametrize("arch,bits,endian", [("amd64", 64, "little"), ("i386", 32, "little"),
                                             ("mips", 32, "big"), ("aarch64", 64, "little")])
@pytest.mark.parametrize("rela", [False, True])
def test_relocation_elf_abi(arch, bits, endian, rela):
    build = engine.build_relocation_table([engine.RelocationSpec(0x123456, 7, 9, -17)], architecture=arch, rela=rela)
    fmt = ("<" if endian == "little" else ">") + ("II" if bits == 32 else "QQ")
    fields = [0x123456, (7 << (8 if bits == 32 else 32)) | 9]
    if rela:
        fmt += "i" if bits == 32 else "q"
        fields.append(-17)
    assert build.payload == struct.pack(fmt, *fields)
    oracle = _elfstructs(bits, endian == "little")
    parsed = (oracle.Elf_Rela if rela else oracle.Elf_Rel).parse(build.payload)
    assert parsed.r_offset == 0x123456 and parsed.r_info_sym == 7 and parsed.r_info_type == 9
    if rela:
        assert parsed.r_addend == -17


def _decode_relr(raw, bits, endian):
    word, base, out = bits // 8, 0, []
    for at in range(0, len(raw), word):
        entry = int.from_bytes(raw[at:at + word], endian)
        if entry & 1:
            out.extend(base + (bit - 1) * word for bit in range(1, bits) if entry & (1 << bit))
            base += (bits - 1) * word
        else:
            out.append(entry)
            base = entry + word
    return out


@pytest.mark.parametrize("bits,endian", [(32, "little"), (32, "big"), (64, "little"), (64, "big")])
def test_relr_boundary_bitmaps_reference_decoder(bits, endian):
    word = bits // 8
    addresses = [0x1000, 0x1000 + word, 0x1000 + 3 * word, 0x1000 + (bits - 1) * word,
                 0x1000 + bits * word, 0x4000]
    build = engine.build_relr_table(list(reversed(addresses)), bits=bits, endian=endian)
    assert _decode_relr(build.payload, bits, endian) == addresses
    assert int.from_bytes(build.payload[word:2 * word], endian) == 1 | 2 | 8 | (1 << (bits - 1))


@pytest.mark.parametrize("bits,endian", [(32, "big"), (64, "little")])
def test_link_map_uses_caller_offsets(bits, endian):
    layout = _layout(bits)
    build = engine.build_link_map_image(layout, base_address=0x4000, l_addr=0x5000, l_name=0x6000,
                                        l_ld=0x7000, l_next=0x8000, l_prev=0x9000, l_info={5: 0xABCD},
                                        extra_fields={"custom": (layout.size - bits // 8, 0x1234)}, endian=endian)
    word = bits // 8
    expected = bytearray(layout.size)
    for offset, value in [(0, 0x5000), (word, 0x6000), (word * 2, 0x7000), (word * 3, 0x8000),
                          (word * 4, 0x9000), (word * 10, 0xABCD), (layout.size - word, 0x1234)]:
        expected[offset:offset + word] = value.to_bytes(word, endian)
    assert build.payload == expected


@pytest.mark.parametrize("arch,code", [("amd64", "Q"), ("i386", "I")])
def test_resolver_stack_layout(arch, code):
    build = engine.build_dl_runtime_resolve_stack(architecture=arch, resolver_entry=0x1000, link_map=0x2000,
        relocation_selector=3, return_address=0x4000, arguments=[5, 6], overflow_offset=7, fill=b"Z")
    assert build.payload == b"Z" * 7 + struct.pack("<" + code * 6, 0x1000, 0x2000, 3, 0x4000, 5, 6)


def _bundle(endian=None):
    return engine.build_dl_fixup_bundle(_layout(), architecture="amd64", image_address=0x400000,
        l_addr=0x400000, symbol_name=b"known_symbol", relocation_target=0x601000, relocation_type=7,
        glibc_version="caller-supplied-test", endian=endian)


def test_fixup_bundle_cross_references():
    build = _bundle()
    data, at = build.payload, build.placements
    assert data[at["symbol_name"]:at["symbol_name"] + 13] == b"known_symbol\x00"
    sym = _elfstructs(64).Elf_Sym.parse(data[at["fake_symbol"]:])
    assert sym.st_name == 1 and sym.st_info.bind == "STB_GLOBAL" and sym.st_info.type == "STT_FUNC"
    assert sym.st_shndx == "SHN_UNDEF"
    rel = _elfstructs(64).Elf_Rela.parse(data[at["jmprel"]:])
    assert rel.r_offset == 0x601000 and rel.r_info_sym == 1 and rel.r_info_type == 7 and rel.r_addend == 0
    tags = dict(struct.iter_unpack("<qQ", data[at["dynamic"]:at["dynamic"] + build.widths["dynamic"]]))
    assert tags[5] == at["string_table"] and tags[6] == at["symbol_table"] and tags[23] == at["jmprel"]
    assert tags[2] == 24 and tags[20] == 7 and tags[11] == 24 and tags[9] == 24


def test_fixup_bundle_endian_override_is_consistent():
    build = _bundle("big")
    assert struct.unpack_from(">QQq", build.payload, build.placements["jmprel"]) == (0x601000, (1 << 32) | 7, 0)


@pytest.mark.parametrize("call", [
    lambda: engine.build_dynamic_vector([(5, -1)]),
    lambda: engine.build_dynamic_vector([(1 << 64, 0)]),
    lambda: engine.build_relocation_table([]),
    lambda: engine.build_relocation_table([engine.RelocationSpec(0, 1 << 32, 0)]),
    lambda: engine.build_relr_table([1]),
    lambda: engine.build_relr_table([8, 8]),
    lambda: engine.build_relr_table([-8]),
    lambda: engine.build_link_map_image(_layout(), base_address=0, l_addr=0, l_name=0, l_ld=0, l_info={24: 0}),
    lambda: engine.build_dl_runtime_resolve_stack(architecture="amd64", resolver_entry=0, link_map=0,
        relocation_selector=0, return_address=0, arguments=list(range(33))),
    lambda: engine.build_dl_fixup_bundle(_layout(), architecture="amd64", image_address=0, l_addr=0,
        symbol_name=b"\x00", relocation_target=0, relocation_type=7, glibc_version="test"),
])
def test_invalid_records_declared_error(call):
    with pytest.raises(engine.BuildError):
        call()


def test_caps_and_seeded_record_fuzz(monkeypatch):
    monkeypatch.setattr(engine, "MAX_RECORDS", 8)
    for call in [lambda: engine.build_dynamic_vector([(5, 1)] * 9),
                 lambda: engine.build_relocation_table([engine.RelocationSpec(0, 0, 0)] * 9),
                 lambda: engine.build_relr_table(list(range(0, 72, 8)))]:
        with pytest.raises(engine.BuildError):
            call()
    rng = random.Random(0xE1F)
    for _ in range(32):
        value = rng.randrange(-(1 << 65), 1 << 65)
        for call in [lambda: engine.build_dynamic_vector([(5, value)]),
                     lambda: engine.build_relocation_table([engine.RelocationSpec(value, 1, 7)]),
                     lambda: engine.build_relr_table([value])]:
            try:
                result = call()
                assert len(result.payload) <= 32
            except engine.BuildError:
                pass


@pytest.mark.parametrize("call", [
    lambda: engine.build_dynamic_vector(None),
    lambda: engine.build_relocation_table([engine.RelocationSpec(0, 0, 0)], architecture=[]),
    lambda: engine.build_relr_table([[8]]),
    lambda: engine.build_relr_table([8, "16"]),
    lambda: dataclasses.replace(_layout(), size=None).validate(),
    lambda: engine.build_link_map_image(None, base_address=0, l_addr=0, l_name=0, l_ld=0),
    lambda: engine.build_dl_runtime_resolve_stack(architecture="amd64", resolver_entry=0, link_map=0,
        relocation_selector=0, return_address=0, arguments=None),
])
def test_malformed_argument_declared_error(call):
    try:
        call()
    except engine.BuildError:
        pass
