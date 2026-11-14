"""Independent vectors and fail-closed fuzz for pwnkern offline engines."""

from __future__ import annotations

import random

import pytest
from capstone import (
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_RISCV,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    CS_MODE_RISCV64,
    Cs,
)

import pwnkern_linux_heap as linux
import pwnkern_multiarch_gadgets as gadgets
import pwnkern_windows_kernel as windows


RNG = random.Random(0xDB_2026)


def _closed(call, declared_error):
    """A fuzz case may be accepted or rejected, but may not leak another error."""

    try:
        return call()
    except declared_error:
        return None
    except Exception as exc:  # pragma: no cover - this is the failure under test
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def _capstone(architecture, mode, raw, address=0x1000):
    """Fresh Capstone instance: independent of the engine's decoder object."""

    return [
        (item.mnemonic, item.op_str, bytes(item.bytes), item.size)
        for item in Cs(architecture, mode).disasm(raw, address)
    ]


# ---------------------------------------------------------------------------
# Linux kernel heap: documented layouts and arithmetic.


def test_linux_msg_layout_and_page_split_match_hand_built_oracles():
    fields = (0x1110, 0x2220, 3, 0x55, 0, 0x3330)
    text = b"CSCTF"
    built = linux.serialize_msg_msg(
        m_list_next=fields[0],
        m_list_prev=fields[1],
        m_type=fields[2],
        m_ts=fields[3],
        next_segment=fields[4],
        security=fields[5],
        text=text,
    )
    independent = b"".join(value.to_bytes(8, "little") for value in fields) + text
    assert built.payload == independent
    assert [(item.name, item.offset, item.width) for item in built.placements] == [
        ("m_list.next", 0x00, 8),
        ("m_list.prev", 0x08, 8),
        ("m_type", 0x10, 8),
        ("m_ts", 0x18, 8),
        ("next", 0x20, 8),
        ("security", 0x28, 8),
        ("text", 0x30, len(text)),
    ]

    segment = linux.serialize_msg_msgseg(next_segment=0x4440, text=b"XY")
    assert segment.payload == (0x4440).to_bytes(8, "little") + b"XY"

    # Upstream formulas: DATALEN_MSG=PAGE_SIZE-48; DATALEN_SEG=PAGE_SIZE-8.
    length = (4096 - 48) + (4096 - 8) + 1
    plan = linux.plan_msg_allocations(length, page_size=4096)
    assert [
        (span.kind, span.payload_offset, span.payload_length, span.allocation_size)
        for span in plan.spans
    ] == [
        ("msg_msg", 0, 4048, 4096),
        ("msg_msgseg", 4048, 4088, 4096),
        ("msg_msgseg", 8136, 1, 9),
    ]
    assert plan.total_allocation_bytes == 4096 + 4096 + 9


def test_linux_cross_cache_dirtycred_and_pg_vec_hand_arithmetic():
    # 8 KiB slab, 16-byte alignment: 96 -> 96, 200 -> 208.
    cross = linux.plan_cross_cache(
        source_object_size=96,
        target_object_size=200,
        page_size=4096,
        slab_order=1,
        object_alignment=16,
        per_cpu_partial_slabs=1,
        release_slabs=2,
        reclaim_slabs=3,
        safety_slabs=1,
    )
    assert cross.slab_bytes == 8192
    assert cross.source_objects_per_slab == 8192 // 96 == 85
    assert cross.target_objects_per_slab == 8192 // 208 == 39
    assert [phase.object_count for phase in cross.phases] == [170, 255, 1, 170, 117]

    dirty = linux.plan_dirtycred(
        variant="cred", blocking_mechanism="filesystem-lock", free_primitive="uaf-free"
    )
    assert dirty.variant == "cred"
    assert [phase.index for phase in dirty.phases] == [1, 2, 3, 4, 5, 6]
    assert "uaf-free" in dirty.phases[2].detail

    pointers = (0x1000, 0x9000)
    vector = linux.build_usma_pg_vec(
        pointers,
        block_count=2,
        block_size=8192,
        mapping_length=16384,
        page_size=4096,
        access_path="existing-cap-net-raw",
    )
    expected = b"".join(pointer.to_bytes(8, "little") for pointer in pointers)
    assert vector.payload == expected
    assert vector.pages_per_block == 2
    assert vector.mapping_pages == 4


def test_linux_serializers_fail_closed_fuzz_all_blob_shapes():
    valid = b"ABCDEFGH"
    flipped = bytes([valid[0] ^ 0x80]) + valid[1:]
    oversized = bytearray(linux.MAX_MESSAGE_LENGTH + 1)
    corpus = (
        ("empty", b""),
        ("random", RNG.randbytes(31)),
        ("truncated-valid", valid[:-1]),
        ("bit-flipped", flipped),
        ("oversized", oversized),
    )
    for _label, blob in corpus:
        _closed(
            lambda blob=blob: linux.serialize_msg_msg(
                m_list_next=0,
                m_list_prev=0,
                m_type=1,
                m_ts=len(blob),
                next_segment=0,
                security=0,
                text=blob,
            ),
            linux.PwnkernLinuxError,
        )
        _closed(
            lambda blob=blob: linux.serialize_msg_msgseg(next_segment=0, text=blob),
            linux.PwnkernLinuxError,
        )


@pytest.mark.parametrize(
    "label,value",
    [
        ("empty", 0),
        ("random", int.from_bytes(random.Random(0x51).randbytes(8), "little")),
        ("truncated-valid", 4047),
        ("bit-flipped", 4048 ^ 0x800),
        ("oversized", linux.MAX_MESSAGE_LENGTH + 1),
    ],
)
def test_linux_message_planner_fail_closed_fuzz(label, value):
    _closed(lambda: linux.plan_msg_allocations(value), linux.PwnkernLinuxError)


@pytest.mark.parametrize(
    "label,source_size",
    [
        ("empty", 0),
        ("random", 137),
        ("truncated-valid", 95),
        ("bit-flipped", 96 ^ 0x40),
        ("oversized", linux.MAX_SLAB_BYTES + 1),
    ],
)
def test_linux_cross_cache_fail_closed_fuzz(label, source_size):
    _closed(
        lambda: linux.plan_cross_cache(
            source_object_size=source_size, target_object_size=192
        ),
        linux.PwnkernLinuxError,
    )


@pytest.mark.parametrize(
    "label,variant",
    [
        ("empty", ""),
        ("random", "random-choice"),
        ("truncated-valid", "fil"),
        ("bit-flipped", "gile"),
        ("oversized", "x" * 100_000),
    ],
)
def test_linux_dirtycred_fail_closed_fuzz(label, variant):
    _closed(
        lambda: linux.plan_dirtycred(
            variant=variant,
            blocking_mechanism="fuse",
            free_primitive="uaf-free",
        ),
        linux.PwnkernLinuxError,
    )


@pytest.mark.parametrize(
    "label,pointers,count,block,mapping",
    [
        ("empty", [], 1, 4096, 4096),
        ("random", [0x5000], 1, 4096, 4096),
        ("truncated-valid", [0x1000], 2, 4096, 8192),
        ("bit-flipped", [0x1001], 1, 4096, 4096),
        ("oversized", [1 << 65], 1, 4096, 4096),
    ],
)
def test_linux_pg_vec_fail_closed_fuzz(label, pointers, count, block, mapping):
    _closed(
        lambda: linux.build_usma_pg_vec(
            pointers,
            block_count=count,
            block_size=block,
            mapping_length=mapping,
        ),
        linux.PwnkernLinuxError,
    )


def test_linux_cli_fuzz_never_raises(capsys):
    cases = (
        [],
        ["random-command"],
        ["msg-spans"],
        ["msg-spanr", "1"],
        ["msg-spans", "9" * 5000],
    )
    for argv in cases:
        assert isinstance(linux.main(argv), int)
        capsys.readouterr()


# ---------------------------------------------------------------------------
# Multiarch gadgets: published encodings checked with independent Capstone.


@pytest.mark.parametrize(
    "architecture,capstone_arch,capstone_mode,raw,decoded,primitive,delta",
    [
        (
            "aarch64",
            CS_ARCH_ARM64,
            CS_MODE_LITTLE_ENDIAN,
            bytes.fromhex("20005fd6"),  # RET X1, ARM ARM encoding D65F0020
            [("ret", "x1", bytes.fromhex("20005fd6"), 4)],
            "instruction-sequence",
            0,
        ),
        (
            "mips32le",
            CS_ARCH_MIPS,
            CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN,
            bytes.fromhex("0800e003e0ffbd27"),  # jr ra; addiu sp,sp,-0x20
            [
                ("jr", "$ra", bytes.fromhex("0800e003"), 4),
                ("addiu", "$sp, $sp, -0x20", bytes.fromhex("e0ffbd27"), 4),
            ],
            "mips32-return",
            -0x20,
        ),
        (
            "rv64",
            CS_ARCH_RISCV,
            CS_MODE_RISCV64,
            bytes.fromhex("67800200"),  # jalr x0, x5, 0 (jr t0)
            [("jr", "t0", bytes.fromhex("67800200"), 4)],
            "riscv-indirect-jump",
            0,
        ),
    ],
)
def test_multiarch_published_instruction_bytes_lock_to_capstone(
    architecture, capstone_arch, capstone_mode, raw, decoded, primitive, delta
):
    assert _capstone(capstone_arch, capstone_mode, raw) == decoded
    plan = gadgets.analyze_gadget(architecture, raw, address=0x1000)
    assert [
        (item.mnemonic, item.operands, item.raw, item.size)
        for item in plan.instructions
    ] == decoded
    assert plan.primitive == primitive
    assert plan.stack_delta == delta


def test_aarch64_frame_is_exact_manual_little_endian_stack_image():
    epilogue = bytes.fromhex("fd7bc1a8c0035fd6")
    # Independent decoder first proves both instructions and byte coverage.
    assert _capstone(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, epilogue, 0x401000) == [
        ("ldp", "x29, x30, [sp], #0x10", bytes.fromhex("fd7bc1a8"), 4),
        ("ret", "", bytes.fromhex("c0035fd6"), 4),
    ]
    frame = gadgets.build_aarch64_epilogue_frame(
        epilogue,
        gadget_address=0x401000,
        frame_address=0x500000,
        next_frame_pointer=0x500100,
        continuation=0x402004,
    )
    assert frame.payload == (0x500100).to_bytes(8, "little") + (0x402004).to_bytes(8, "little")
    assert frame.absolute_placements() == {
        "next_frame_pointer": 0x500000,
        "continuation": 0x500008,
    }


def test_multiarch_analyzer_and_frame_fail_closed_fuzz():
    valid = bytes.fromhex("fd7bc1a8c0035fd6")
    flipped = valid[:2] + bytes([valid[2] ^ 0x40]) + valid[3:]
    corpus = (
        ("empty", b""),
        ("random", random.Random(0xA64).randbytes(8)),
        ("truncated-valid", valid[:-1]),
        ("bit-flipped", flipped),
        ("oversized", b"\x00" * (gadgets.MAX_GADGET_BYTES + 1)),
    )
    for _label, blob in corpus:
        _closed(
            lambda blob=blob: gadgets.analyze_gadget("aarch64", blob, address=0x401000),
            gadgets.PwnkernGadgetError,
        )
        _closed(
            lambda blob=blob: gadgets.build_aarch64_epilogue_frame(
                blob,
                gadget_address=0x401000,
                frame_address=0x500000,
                next_frame_pointer=0x500100,
                continuation=0x402004,
            ),
            gadgets.PwnkernGadgetError,
        )


def test_multiarch_cli_fuzz_never_raises(capsys):
    valid = "fd7bc1a8c0035fd6"
    cases = (
        [],
        ["random"],
        ["analyze", "aarch64"],
        ["analyze", "aarch64", valid[:-1]],
        ["analyze", "aarch64", "0" * ((gadgets.MAX_GADGET_BYTES + 1) * 2)],
    )
    for argv in cases:
        assert isinstance(gadgets.main(argv), int)
        capsys.readouterr()


# ---------------------------------------------------------------------------
# Windows kernel: Microsoft CTL_CODE/buffer semantics and EX_FAST_REF math.


def test_windows_documented_ctl_code_and_buffer_contract_vector():
    # ntdddisk.h IOCTL_DISK_GET_PARTITION_INFO:
    # CTL_CODE(FILE_DEVICE_DISK=7, function=1, METHOD_BUFFERED, FILE_READ_ACCESS).
    expected = (7 << 16) | (1 << 14) | (1 << 2) | 0
    assert expected == 0x00074004
    assert windows.encode_ioctl(7, 1, 0, 1) == expected
    decoded = windows.decode_ioctl(expected)
    assert (decoded.device_type, decoded.function, decoded.method, decoded.access) == (
        7, 1, 0, 1
    )

    # Microsoft METHOD_BUFFERED semantics: one system buffer sized to max(in,out).
    contract = windows.plan_device_io_control(
        expected, input_length=17, output_length=65
    )
    assert contract.input_carrier == "Irp.AssociatedIrp.SystemBuffer"
    assert contract.output_carrier == "Irp.AssociatedIrp.SystemBuffer"
    assert contract.system_buffer_size == 65
    assert contract.mdl_length == 0
    assert contract.raw_user_pointers is False


def test_windows_fast_ref_transfer_matches_independent_bit_and_byte_math():
    values = {
        "current_eprocess": 0xFFFFF80000001000,
        "system_eprocess": 0xFFFFF80000002000,
        "token_offset": 0x4B8,
        "current_token_value": 0xFFFFA0001234500D,
        "system_token_value": 0xFFFFA000ABCDF002,
        "ref_bits": 4,
    }
    result = windows.build_token_transfer(**values)
    mask = (1 << values["ref_bits"]) - 1
    pointer_mask = ((1 << 64) - 1) ^ mask
    expected = (values["system_token_value"] & pointer_mask) | (
        values["current_token_value"] & mask
    )
    assert result.write_value == expected == 0xFFFFA000ABCDF00D
    assert result.write_bytes == expected.to_bytes(8, "little")
    assert result.write_address == values["current_eprocess"] + values["token_offset"]


@pytest.mark.parametrize(
    "label,fields",
    [
        ("empty", (0, 0, 0, 0)),
        ("random", (0x8337, 0xA5B, 2, 3)),
        ("truncated-valid", (0x37, 0xA5, 2, 3)),
        ("bit-flipped", (0x8337 ^ 0x80, 0xA5B, 2, 3)),
        ("oversized", (1 << 16, 0, 0, 0)),
    ],
)
def test_windows_ioctl_encoder_fail_closed_fuzz(label, fields):
    _closed(lambda: windows.encode_ioctl(*fields), windows.PwnkernWindowsError)


@pytest.mark.parametrize(
    "label,raw",
    [
        ("empty", b""),
        ("random", random.Random(0xC71).randbytes(4)),
        ("truncated-valid", bytes.fromhex("044007")),
        ("bit-flipped", bytes.fromhex("04400700")[:-1] + b"\x80"),
        ("oversized", b"\xff" * 8),
    ],
)
def test_windows_ioctl_decoder_fail_closed_fuzz(label, raw):
    code = int.from_bytes(raw, "little")
    _closed(lambda: windows.decode_ioctl(code), windows.PwnkernWindowsError)


@pytest.mark.parametrize(
    "label,code,input_length,output_length",
    [
        ("empty", 0, 0, 0),
        ("random", 0x8337E96A, 123, 456),
        ("truncated-valid", 0x74004 & 0xFFFF, 17, 65),
        ("bit-flipped", 0x74004 ^ 0x2, 17, 65),
        ("oversized", 1 << 32, 1 << 32, 1 << 32),
    ],
)
def test_windows_buffer_planner_fail_closed_fuzz(label, code, input_length, output_length):
    _closed(
        lambda: windows.plan_device_io_control(
            code, input_length=input_length, output_length=output_length
        ),
        windows.PwnkernWindowsError,
    )


def test_windows_token_transfer_fail_closed_fuzz():
    valid = {
        "current_eprocess": 0xFFFFF80000001000,
        "system_eprocess": 0xFFFFF80000002000,
        "token_offset": 0x4B8,
        "current_token_value": 0xFFFFA0001234500D,
        "system_token_value": 0xFFFFA000ABCDF002,
        "ref_bits": 4,
    }
    cases = {
        "empty": {key: 0 for key in valid},
        "random": {**valid, "token_offset": 0x4BA},
        "truncated-valid": {**valid, "system_token_value": 0xF002},
        "bit-flipped": {**valid, "current_eprocess": valid["current_eprocess"] ^ 1},
        "oversized": {**valid, "system_eprocess": 1 << 64},
    }
    for _label, kwargs in cases.items():
        _closed(lambda kwargs=kwargs: windows.build_token_transfer(**kwargs), windows.PwnkernWindowsError)


def test_windows_cli_fuzz_never_raises(capsys):
    cases = (
        [],
        ["random-command"],
        ["decode"],
        ["decode", "0x7400"],  # truncated but valid 32-bit integer
        ["decode", "9" * 5000],
    )
    for argv in cases:
        assert isinstance(windows.main(argv), int)
        capsys.readouterr()
