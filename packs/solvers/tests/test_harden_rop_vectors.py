"""Independent vector locks and fail-closed fuzz for the offline ROP toolkits.

Oracles:
* Capstone 5 disassembles gadget bytes independently of gadget_catalog.
* pyelftools reads the hand-built libc ELF independently of one_gadget.
* david942j/one_gadget's official README supplies constraint/output examples.
* ROP and printf payloads are checked against hand-packed ABI/count semantics;
  format_string_builder.simulate_positional_writes is never used as an oracle.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import random
import re
import struct

from capstone import (
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_LITTLE_ENDIAN,
    Cs,
)
from elftools.elf.elffile import ELFFile
import pytest

import format_string_builder as fmt
import gadget_catalog as gadgets
import one_gadget as one
import stack_migration as migration
from contract import BuildError, PayloadBuild
from gadget_catalog import Gadget, GadgetCatalog


BUILD_ID = bytes.fromhex("00112233445566778899aabbccddeeff01020304")


def _elf64_segment(code: bytes, *, machine: int = 62) -> tuple[bytes, int]:
    """Hand-encode one executable ELF64 PT_LOAD from the System V ABI."""
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    code_offset = 64 + 56
    virtual = 0x400000 + code_offset
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, machine, 1, virtual, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    program = struct.pack(
        "<IIQQQQQQ", 1, 5, code_offset, virtual, virtual,
        len(code), len(code), 0x1000,
    )
    return header + program + code, virtual


def _elf32_segment(code: bytes) -> tuple[bytes, int]:
    """Hand-encode one executable ELF32 i386 PT_LOAD."""
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + bytes(8)
    code_offset = 52 + 32
    virtual = 0x8048000 + code_offset
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2, 3, 1, virtual, 52, 0, 0, 52, 32, 1, 0, 0, 0,
    )
    program = struct.pack(
        "<IIIIIIII", 1, code_offset, virtual, virtual,
        len(code), len(code), 5, 0x1000,
    )
    return header + program + code, virtual


def _libc_fixture() -> bytes:
    """Hand-encode PT_LOAD + aligned GNU build-id PT_NOTE."""
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    phoff, phnum, code_offset = 64, 2, 64 + 2 * 56
    code = b"\x90" * 0x100
    note = struct.pack("<III", 4, len(BUILD_ID), 3) + b"GNU\x00" + BUILD_ID
    note_offset = code_offset + len(code)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3, 62, 1, 0x1000, phoff, 0, 0, 64, 56, phnum, 0, 0, 0,
    )
    load = struct.pack(
        "<IIQQQQQQ", 1, 5, code_offset, 0x1000, 0x1000,
        len(code), len(code), 0x1000,
    )
    notes = struct.pack(
        "<IIQQQQQQ", 4, 4, note_offset, 0, 0,
        len(note), len(note), 4,
    )
    return header + load + notes + code + note


def _sentinel_catalog(delta: int = 0) -> GadgetCatalog:
    base = 0x1122334455667000 + delta
    rows = (
        Gadget(base + 0x10, 0x10, "pop rdi ; ret", b"\x5f\xc3", 16, ("rdi",)),
        Gadget(base + 0x20, 0x20, "pop rsi ; ret", b"\x5e\xc3", 16, ("rsi",)),
        Gadget(base + 0x30, 0x30, "pop rdx ; ret", b"\x5a\xc3", 16, ("rdx",)),
        Gadget(base + 0x40, 0x40, "pop rsp ; ret", b"\x5c\xc3", 16, ("rsp",)),
        Gadget(base + 0x50, 0x50, "leave ; ret", b"\xc9\xc3", 16, ("rbp", "rsp")),
    )
    return GadgetCatalog("amd64", 64, "little", 2, base, rows)


def _capstone(raw: bytes, architecture: int, mode: int) -> list[tuple[str, str]]:
    decoder = Cs(architecture, mode)
    rows = [(instruction.mnemonic, instruction.op_str) for instruction in decoder.disasm(raw, 0)]
    assert sum(instruction.size for instruction in decoder.disasm(raw, 0)) == len(raw)
    return rows


@pytest.mark.parametrize(
    "raw,semantic,decoded",
    [
        (bytes.fromhex("5fc3"), "pop rdi ; ret", [("pop", "rdi"), ("ret", "")]),
        (bytes.fromhex("415fc3"), "pop r15 ; ret", [("pop", "r15"), ("ret", "")]),
        (bytes.fromhex("0f05c3"), "syscall ; ret", [("syscall", ""), ("ret", "")]),
        (bytes.fromhex("4894c3"), "xchg rax, rsp ; ret", [("xchg", "rsp, rax"), ("ret", "")]),
        (bytes.fromhex("4889c4c3"), "mov rsp, rax ; ret", [("mov", "rsp, rax"), ("ret", "")]),
        (
            bytes.fromhex("5b5d415c415d415e415fc3"),
            "csu pop rbx rbp r12 r13 r14 r15 ; ret",
            [("pop", "rbx"), ("pop", "rbp"), ("pop", "r12"),
             ("pop", "r13"), ("pop", "r14"), ("pop", "r15"), ("ret", "")],
        ),
        (
            bytes.fromhex("4c89fa4c89f64489ef41ff14dc"),
            "csu call [r12+rbx*8] (r13d,r14,r15)",
            [("mov", "rdx, r15"), ("mov", "rsi, r14"),
             ("mov", "edi, r13d"), ("call", "qword ptr [r12 + rbx*8]")],
        ),
    ],
)
def test_amd64_gadget_bytes_lock_to_capstone(raw, semantic, decoded):
    assert _capstone(raw, CS_ARCH_X86, CS_MODE_64) == decoded
    elf, address = _elf64_segment(raw)
    match = gadgets.catalog_elf(elf).require(semantic)
    assert (match.address, match.file_offset, match.raw) == (address, 120, raw)


@pytest.mark.parametrize(
    "raw,semantic,decoded",
    [
        (bytes.fromhex("58c3"), "pop eax ; ret", [("pop", "eax"), ("ret", "")]),
        (bytes.fromhex("cd80c3"), "int 0x80 ; ret", [("int", "0x80"), ("ret", "")]),
        (bytes.fromhex("94c3"), "xchg eax, esp ; ret", [("xchg", "esp, eax"), ("ret", "")]),
    ],
)
def test_i386_gadget_bytes_lock_to_capstone(raw, semantic, decoded):
    assert _capstone(raw, CS_ARCH_X86, CS_MODE_32) == decoded
    elf, address = _elf32_segment(raw)
    match = gadgets.catalog_elf(elf).require(semantic)
    assert (match.address, match.file_offset, match.raw) == (address, 84, raw)


def test_aarch64_alignment_and_bytes_lock_to_capstone():
    raw = bytes.fromhex("c0035fd6010000d400021fd6")
    assert _capstone(raw, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) == [
        ("ret", ""), ("svc", "#0"), ("br", "x16")
    ]
    elf, address = _elf64_segment(raw, machine=183)
    result = gadgets.catalog_elf(elf, load_bias=0x12345000)
    assert result.by_semantic() == {
        "br x16": (address + 8 + 0x12345000,),
        "ret": (address + 0x12345000,),
        "svc #0": (address + 4 + 0x12345000,),
    }


def test_catalog_projection_and_selection_use_only_caller_bias():
    code = bytes.fromhex("905fc358c3")
    elf, address = _elf64_segment(code)
    bias = 0x23456000
    result = gadgets.catalog_elf(elf, load_bias=bias)
    assert result.find("pop rdi ; ret")[0].address == address + 1 + bias
    assert result.first("pop rax ; ret").address == address + 3 + bias
    assert gadgets.select_addresses(result, ("pop rdi ; ret", "pop rax ; ret")) == {
        "pop rdi ; ret": address + 1 + bias,
        "pop rax ; ret": address + 3 + bias,
    }
    with pytest.raises(LookupError):
        result.require("caller-did-not-supply-this")


def test_libc_identity_matches_pyelftools_and_hashlib():
    data = _libc_fixture()
    reference = ELFFile(BytesIO(data))
    executable = tuple(
        (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"])
        for segment in reference.iter_segments()
        if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1
    )
    build_ids = [
        note["n_desc"]
        for segment in reference.iter_segments()
        if segment["p_type"] == "PT_NOTE"
        for note in segment.iter_notes()
        if note["n_type"] == "NT_GNU_BUILD_ID"
    ]
    identity = one.identify_libc(data)
    assert identity.sha256 == hashlib.sha256(data).hexdigest()
    assert (identity.bits, identity.endian, identity.machine) == (64, "little", "amd64")
    assert identity.executable_ranges == executable == ((0x1000, 0x1100),)
    assert identity.build_id == build_ids[0] == BUILD_ID.hex()
    assert identity.contains_executable_offset(0x1000)
    assert not identity.contains_executable_offset(0x1100)


OFFICIAL_ONE_GADGET = '''
0xe3b31 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], ...} is a valid argv
'''


def test_official_one_gadget_output_and_null_or_semantics():
    parsed = one.parse_one_gadget_output(OFFICIAL_ONE_GADGET)
    assert [candidate.offset for candidate in parsed] == [0xE3B31, 0x4F322]
    assert parsed[0].constraints == (
        "[r15] == NULL || r15 == NULL || r15 is a valid argv",
        "[rdx] == NULL || rdx == NULL || rdx is a valid envp",
    )
    # Boolean oracle: both documented disjunctions are true because r15=rdx=0.
    solved = one.solve_one_gadget_constraints(
        parsed[0].constraints,
        register_state={"r15": 0, "rdx": 0},
        stack_pointer=0x7000,
    )
    assert solved.satisfiable is True
    assert solved.register_assignments == ()
    assert solved.chosen_branches == ("r15 == NULL", "rdx == NULL")


def test_official_stack_null_branch_and_documented_writable_alignment():
    parsed = one.parse_one_gadget_output(OFFICIAL_ONE_GADGET)
    stack = one.solve_one_gadget_constraints(
        parsed[1].constraints,
        register_state={},
        stack_pointer=0x7000,
        controllable_stack_offsets={0x40},
    )
    assert stack.satisfiable and stack.stack_assignments == ((0x40, 0),)

    solved = one.solve_one_gadget_constraints(
        ("address rbp-0x78 is writable", "rsp & 0xf == 0"),
        register_state={"rbp": 0x8080},
        stack_pointer=0x7000,
        writable_ranges=((0x8000, 0x8100),),
    )
    assert solved.satisfiable is True  # rbp-0x78=0x8008 and 0x7000 is 16-byte aligned.


def test_one_gadget_conjunction_uses_final_register_state():
    # All constraints are conjunctive. Setting rax=0 to meet the second clause
    # makes the first clause false because 0 is outside the writable range.
    solution = one.solve_one_gadget_constraints(
        ("address rax is writable", "rax == NULL"),
        register_state={"rax": 0x8080},
        controllable_registers={"rax"},
        stack_pointer=0x7000,
        writable_ranges=((0x8000, 0x9000),),
    )
    assert solution.satisfiable is False


def test_one_gadget_plan_is_fully_caller_address_parameterized():
    libc_base = 0x712345670000
    gadget_offset = 0x1010
    loader = 0x1A2B3C4D5E6F7081
    payload_address = 0x600000
    expected = b"Z" * 3 + struct.pack("<QQQ", loader, 0, libc_base + gadget_offset)
    build = one.build_one_gadget_plan(
        _libc_fixture(),
        libc_base=libc_base,
        gadget_offset=gadget_offset,
        constraints=("rax == NULL",),
        register_state={"rax": 9},
        controllable_registers={"rax"},
        register_loaders={"rax": loader},
        stack_pointer=payload_address + len(expected),
        overflow_offset=3,
        payload_address=payload_address,
        fill=b"Z",
    )
    assert build.payload == expected
    assert build.slice("loader.rax") == struct.pack("<Q", loader)
    assert build.slice("one_gadget") == struct.pack("<Q", libc_base + gadget_offset)


def test_stack_builders_match_hand_packed_caller_addresses():
    catalog = _sentinel_catalog()
    pivot_address = catalog.require("pop rsp ; ret").address
    new_stack = 0x2233445566778800
    pivot_catalog = migration.catalog_pivots(catalog)
    pivot = pivot_catalog.choose(("pop-sp",))
    assert pivot_catalog.find("pop-sp") == (pivot,)
    stage = migration.build_pivot_stage(
        pivot, new_stack_address=new_stack, overflow_offset=3, fill=b"Q"
    )
    assert stage.payload == b"Q" * 3 + struct.pack("<QQ", pivot_address, new_stack)

    selected = migration.build_catalog_pivot_stage(
        catalog, new_stack_address=new_stack + 0x100,
        preferences=("pop-sp",), overflow_offset=1, fill=b"R",
    )
    assert selected.payload == b"R" + struct.pack("<QQ", pivot_address, new_stack + 0x100)

    stage2 = b"CALLER_STAGE_TWO"
    read_address = 0x3344556677889900
    destination = 0x445566778899A000
    migrated = migration.build_read_then_migrate_amd64(
        catalog, read_address=read_address, destination=destination,
        stage2=stage2, overflow_offset=2, fd=7, fill=b"S",
    )
    expected_words = (
        catalog.require("pop rdi ; ret").address, 7,
        catalog.require("pop rsi ; ret").address, destination,
        catalog.require("pop rdx ; ret").address, len(stage2),
        read_address, pivot_address, destination,
    )
    assert migrated.payload == b"SS" + struct.pack("<9Q", *expected_words) + stage2

    frame_a, frame_b = 0x5566778899AAB000, 0x5566778899AAC000
    continuation_a, continuation_b = 0x66778899AABBCC00, 0x778899AABBCCDD00
    hops = (
        migration.LeaveHop(frame_a, frame_b, continuation_a),
        migration.LeaveHop(frame_b, 0, continuation_b),
    )
    bundle = migration.build_leave_hop_bundle(hops)
    assert bundle.payload == struct.pack("<4Q", frame_b, continuation_a, 0, continuation_b)
    assert bundle.metadata["frame_addresses"] == f"{frame_a:#x},{frame_b:#x}"


def test_format_vectors_use_hand_counting_and_caller_addresses():
    target = 0x1122334455667788
    build = fmt.build_fmt_writes(
        {target: b"\x05\x02"}, first_address_arg=20,
        value_width=2, atom_size=1, prefix=b"AB",
    )
    expected_format = b"AB%20$hhn%20$3c%21$hhnPP"
    expected = expected_format + struct.pack("<QQ", target + 1, target)
    assert build.payload == expected
    # Independent printf accounting: literal 'AB'=2, first %hhn writes 2;
    # %20$3c advances to 5, and the second %hhn writes 5.
    count = len(b"AB")
    expected_memory = {target + 1: count % 256}
    count += 3
    expected_memory[target] = count % 256
    assert expected_memory == {target + 1: 2, target: 5}

    got = 0x2233445566778890
    replacement = 0x0502
    overwrite = fmt.build_fmt_got_overwrite(
        got_address=got, replacement_address=replacement,
        first_address_arg=20, partial_width=2, atom_size=1, prefix=b"AB",
    )
    expected_overwrite = expected_format + struct.pack("<QQ", got, got + 1)
    assert overwrite.payload == expected_overwrite
    assert overwrite.metadata["got_address"] == hex(got)
    assert overwrite.metadata["replacement_address"] == hex(replacement)


def test_probe_discovery_and_positional_leak_documented_printf_semantics():
    probe = fmt.build_offset_probe(
        start=3, stop=5, marker=b"MARK", separator=b":", word_size=4
    )
    assert probe.payload == b"MARK:%3$p:%4$p:%5$p"
    marker_word = int.from_bytes(b"MARK", "little")
    assert fmt.discover_marker_slot(
        f"0x0|{marker_word:#x}|0x7", marker=b"MARK", word_size=4, start=3
    ) == 4

    address = 0x0102030405060708
    leak = fmt.build_positional_leak(
        argument_index=7, conversion="s", address=address,
        prefix=b"<", suffix=b">", max_bytes=4,
    )
    assert leak.payload == b"<%7$.4s>" + struct.pack("<Q", address)


def test_format_simulator_matches_independently_authored_printf_payload():
    # This payload is authored here, not returned by a builder: two literal
    # bytes, %8$hhn stores 2, %8$3c advances to 5, then %9$hhn stores 5.
    text = b"AB%8$hhn%8$3c%9$hhn"
    first, second = 0x4141414141414000, 0x4242424242424000
    manual = PayloadBuild(
        text + struct.pack("<QQ", first, second),
        {
            "address_table": len(text),
            "write[0].address": len(text),
            "write[1].address": len(text) + 8,
        },
        architecture="amd64",
        strategy="fmt-positional-arbitrary-write",
        metadata={"atom_size": "1", "first_address_arg": "8"},
    )
    assert fmt.simulate_positional_writes(manual) == {first: 2, second: 5}


def _assert_only(function, allowed, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except Exception as exc:  # Deliberately inspect the public exception boundary.
        assert isinstance(exc, allowed), (
            f"{function.__module__}.{function.__name__} leaked {type(exc).__name__}: {exc}"
        )


def test_malformed_elf_bytes_truncations_flips_and_random_fail_closed():
    rng = random.Random(0xC5C7F2026)
    gadget_elf, _ = _elf64_segment(bytes.fromhex("905fc3"))
    libc_elf = _libc_fixture()
    cases = [b"", b"\x7fELF", bytes(64), b"not an elf"]
    cases += [rng.randbytes(rng.randrange(0, 256)) for _ in range(128)]
    for valid in (gadget_elf, libc_elf):
        cases += [valid[:cut] for cut in range(len(valid))]
        for index in range(len(valid)):
            flipped = bytearray(valid)
            flipped[index] ^= 1 << (index % 8)
            cases.append(bytes(flipped))
    for case in cases:
        _assert_only(gadgets.catalog_elf, gadgets.ELFParseError, case)
        _assert_only(one.identify_libc, BuildError, case)
        _assert_only(
            migration.catalog_pivots,
            (BuildError, gadgets.ELFParseError),
            case,
        )


def test_oversized_binary_guards_fail_closed(monkeypatch):
    monkeypatch.setattr(gadgets, "MAX_ELF_BYTES", 128)
    monkeypatch.setattr(one, "MAX_LIBC", 128)
    with pytest.raises(gadgets.ELFParseError):
        gadgets.catalog_elf(b"A" * 129)
    with pytest.raises(BuildError):
        one.identify_libc(b"A" * 129)


def test_one_gadget_text_and_constraint_fuzz_fail_closed(monkeypatch):
    rng = random.Random(0x0E6AD6E7)
    texts = ["", "constraints:", "garbage", "0x1 x\nconstraints:\n"]
    texts += [rng.randbytes(length).decode("latin-1") for length in range(128)]
    for text in texts:
        _assert_only(one.parse_one_gadget_output, BuildError, text)
    monkeypatch.setattr(one, "MAX_CONSTRAINTS", 8)
    with pytest.raises(BuildError):
        one.solve_one_gadget_constraints(
            tuple("rax == NULL" for _ in range(9)),
            register_state={}, stack_pointer=0,
        )
    malformed = ("", "unknown syntax", "rax == -1", "[rsp+wat] == NULL")
    for constraint in malformed:
        _assert_only(
            one.solve_one_gadget_constraints,
            BuildError,
            (constraint,), register_state={}, stack_pointer=0,
        )


def test_stack_and_format_boundaries_fail_closed(monkeypatch):
    catalog = _sentinel_catalog()
    pivot = migration.catalog_pivots(catalog).choose(("pop-sp",))
    monkeypatch.setattr(migration, "MAX_STAGE", 64)
    with pytest.raises(BuildError):
        migration.build_pivot_stage(pivot, new_stack_address=1, overflow_offset=65)
    with pytest.raises(BuildError):
        migration.build_read_then_migrate_amd64(
            catalog, read_address=1, destination=2,
            stage2=b"X" * 65, overflow_offset=0,
        )
    with pytest.raises(BuildError):
        migration.build_catalog_pivot_stage(
            catalog, new_stack_address=1, preferences=(),
        )
    with pytest.raises(BuildError):
        migration.build_leave_hop_bundle(())
    with pytest.raises(BuildError):
        migration.build_leave_hop_bundle(
            tuple(migration.LeaveHop(index * 16, 0, 0) for index in range(129))
        )

    with pytest.raises(BuildError):
        fmt.build_fmt_writes({}, first_address_arg=1)
    with pytest.raises(BuildError):
        fmt.build_fmt_writes(
            {1: b"A" * 1025}, first_address_arg=1,
            value_width=8, atom_size=1,
        )
    rng = random.Random(0xF07A7)
    for _ in range(128):
        data = rng.randbytes(rng.randrange(0, 128))
        _assert_only(fmt.discover_marker_slot, BuildError, data)


def test_catalog_missing_path_raises_declared_error(tmp_path):
    with pytest.raises(gadgets.ELFParseError):
        gadgets.catalog_elf(tmp_path / "missing.elf")


def test_identify_libc_directory_raises_declared_error(tmp_path):
    with pytest.raises(BuildError):
        one.identify_libc(tmp_path)


def test_constraint_malformed_range_raises_declared_error():
    with pytest.raises(BuildError):
        one.solve_one_gadget_constraints(
            ("rax == NULL",), register_state={"rax": 0},
            stack_pointer=0, writable_ranges=((1,),),
        )


def test_pivot_catalog_malformed_member_raises_declared_error():
    malformed = GadgetCatalog("amd64", 64, "little", 2, 0, (None,))
    with pytest.raises(BuildError):
        migration.catalog_pivots(malformed)


def test_format_simulator_malformed_build_raises_declared_error():
    malformed = PayloadBuild(
        b"", {}, strategy="fmt-positional-arbitrary-write", metadata={}
    )
    with pytest.raises(BuildError):
        fmt.simulate_positional_writes(malformed)


def test_format_write_rejects_address_slot_overflow():
    with pytest.raises(BuildError):
        fmt.build_fmt_writes(
            {0x1000: b"AB"}, first_address_arg=65535,
            value_width=2, atom_size=1,
        )


def test_got_overwrite_rejects_zero_partial_width():
    with pytest.raises(BuildError):
        fmt.build_fmt_got_overwrite(
            got_address=0x404018, replacement_address=0x1234,
            first_address_arg=8, partial_width=0,
        )


def test_marker_discovery_rejects_result_slot_overflow():
    assert fmt.discover_marker_slot(
        "0x0|0x41", marker=b"A", word_size=4, start=65535
    ) is None


def test_format_write_oversized_count_raises_declared_error():
    with pytest.raises(BuildError):
        fmt.build_fmt_writes(
            {0x404000: b"A"}, first_address_arg=8,
            value_width=1, atom_size=1, numbwritten=10**5000,
        )


def test_format_write_rejects_zero_pad_argument():
    with pytest.raises(BuildError):
        fmt.build_fmt_writes(
            {0x404000: b"A"}, first_address_arg=8,
            value_width=1, atom_size=1, pad_argument=0,
        )


def test_format_write_rejects_boolean_atom_size():
    with pytest.raises(BuildError):
        fmt.build_fmt_writes(
            {0x404000: b"A"}, first_address_arg=8,
            value_width=1, atom_size=True,
        )
