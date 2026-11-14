#!/usr/bin/env python3
"""B-164: 32-bit ARM (A32 and Thumb/T32) native emulation for mobile codecs.

The shipped VM declined every armeabi-v7a (32-bit ARM) JNI transform: `native_emulate` ran only x86-64 and
arm64, `_parse_so` fed the flat symbol table from ELF64 alone, and `VM._invoke` failed closed on machine 40.
This widens all three, fail-closed:

  * native_emulate gains ARCH_ARM32 / ARCH_THUMB (Unicorn). A 32-bit ARM function emulates to its value; the
    return is the moment control reaches the caller's return address (the LR canary), so a computed jump is
    never read as one; and an undefined register, the return address, the entry flags, a machine-dependent
    instruction (conditional or not), an A32/Thumb switch inside the body or no return each decline. The runs
    that stand for the undefined entry state give every bit of it both values, start the function at different
    places in its page (so a Thumb literal load, whose word depends on the address modulo 4, declines) and run
    in user mode (verification round 2).
  * _SoBody reads an ELF32 little-endian arm32 .so's FUNC exports as the runnable sentinels EM_ARM_A32 /
    EM_ARM_THUMB (a Thumb symbol's offset masked); _fold_arm32 folds those exports into the lookup table so an
    arm32-only native is found. An EM_ARM definition from any other container (ELF64, big-endian) keeps the
    raw EM_ARM, which every gate declines.
  * _native_dispatch routes the two sentinels through the engine alone, with the JNIEnv/jclass device-pointer
    cross-check, and the invoke gate declines a jlong argument, a jlong return and a proto-less native on
    arm32 (the register-pair ABI this 1-register-per-arg mapping cannot place), a third Java int (a stack
    argument) and a returned 0 (the gate-fail sentinel, as on x86-64).

Every ARM/Thumb fixture is hand-assembled here and its encoding is checked against capstone inside the test,
so nothing depends on an external assembler. The tests that run the engine report NOT RUN (skip) when the
Unicorn engine is unavailable on the host; the pure ELF32-parsing and table tests run regardless.

Run under the network sandbox:
    sandbox-exec -f .../sb.sb .venv/bin/python -m pytest tests/test_b164_native_arm.py -n 2
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "common"))
sys.path.insert(0, str(ROOT / "solvers" / "mobile-android"))

import native_emulate as ne  # noqa: E402
import dex_chain_codec as dcc  # noqa: E402
from ctf.openers import mobile_fixtures as MF  # noqa: E402
from ctf.openers import mobile_splits_synth as MS  # noqa: E402
from ctf.openers.mobile_splits_synth import (Asm, DexWriter, jni_symbol, ACC_PUBLIC,  # noqa: E402
                                             ACC_STATIC, ACC_NATIVE, SB, STR)

UNI = ne.UNICORN_AVAILABLE
needs_uni = pytest.mark.skipif(not UNI, reason="needs the Unicorn engine (%s)" % ne.UNICORN_UNAVAILABLE_REASON)

A32, T32 = dcc.EM_ARM_A32, dcc.EM_ARM_THUMB


# --------------------------------------------------------------------------- hand-assembled ARM/Thumb bodies
def arm(*words: int) -> bytes:
    """Little-endian A32 words."""
    return b"".join(struct.pack("<I", w) for w in words)


def thumb(*halfwords: int) -> bytes:
    """Little-endian T32 (16-bit) halfwords."""
    return b"".join(struct.pack("<H", h) for h in halfwords)


def _disasm(code: bytes, thumb_mode: bool = False):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb_mode else CS_MODE_ARM)
    return [(i.mnemonic, i.op_str) for i in md.disasm(code, 0)]


def _mnems(code: bytes, thumb_mode: bool = False):
    return [m for m, _ in _disasm(code, thumb_mode)]


BX_LR = 0xE12FFF1E
# A32: jint derive(JNIEnv* r0, jclass r1, jint x = r2) { return 3*x + 1; }
#   mov r0, r2 ; add r0, r0, r0, lsl #1 ; add r0, r0, #1 ; bx lr
A32_DERIVE = arm(0xE1A00002, 0xE0800080, 0xE2800001, BX_LR)
# A32, another transform of the same shape: return x + 2.   add r0, r2, #2 ; bx lr
A32_OTHER = arm(0xE2820002, BX_LR)
# T32: jint tderive(... x = r2) { return x + 5; }  mov r0,r2 ; adds r0,#5 ; bx lr
T32_DERIVE = thumb(0x4610, 0x3005, 0x4770)
# AArch64: jint derive64(... x = w2) { return x + 7; }  add w0, w2, #7 ; ret
A64_DERIVE = struct.pack("<II", 0x11001C40, 0xD65F03C0)


def derive(x: int) -> int:
    return (3 * x + 1) & 0xFFFFFFFF


def other(x: int) -> int:
    return (x + 2) & 0xFFFFFFFF


def tderive(x: int) -> int:
    return (x + 5) & 0xFFFFFFFF


def derive64(x: int) -> int:
    return (x + 7) & 0xFFFFFFFF


def test_hand_assembled_bodies_decode_as_intended():
    """The fixtures are the instructions the tests claim (so a bad hand-encoding fails loudly, not silently)."""
    assert _disasm(A32_DERIVE) == [("mov", "r0, r2"), ("add", "r0, r0, r0, lsl #1"),
                                   ("add", "r0, r0, #1"), ("bx", "lr")]
    assert _disasm(A32_OTHER) == [("add", "r0, r2, #2"), ("bx", "lr")]
    assert _disasm(T32_DERIVE, True) == [("mov", "r0, r2"), ("adds", "r0, #5"), ("bx", "lr")]
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    assert [(i.mnemonic, i.op_str) for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(A64_DERIVE, 0)] == [
        ("add", "w0, w2, #7"), ("ret", "")]


# --------------------------------------------------------------------------- native_emulate: the engine layer
@needs_uni
def test_emulate_arm32_and_thumb_compute_their_value():
    # r0..r3 are the AAPCS args; derive reads r2, so args = [env, jclass, x]
    assert ne.emulate_arm32_aapcs(A32_DERIVE, [0, 0, 11]) == derive(11)
    assert ne.emulate_arm32_aapcs(T32_DERIVE, [0, 0, 20], thumb=True) == tderive(20)


@needs_uni
def test_emulate_arm32_reading_an_undefined_register_declines():
    # mul r0, r2, r3 ; bx lr  -- r3 is never set, so the poison runs disagree -> fail closed
    body = arm(0xE0000392, BX_LR)
    assert _disasm(body)[0] == ("mul", "r0, r2, r3")
    with pytest.raises(ne.EmulationError, match="depends on an undefined register"):
        ne.emulate_arm32_aapcs(body, [0, 0, 7])


@needs_uni
def test_emulate_arm32_machine_dependent_instruction_declines():
    # mrc p15,0,r0,c13,c0,3 (read TPIDRURO, the thread pointer) ; bx lr  -- machine-dependent, must decline
    body = arm(0xEE1D0F70, BX_LR)
    assert _mnems(body)[0] == "mrc"
    with pytest.raises(ne.EmulationError, match="mrc executed"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])
    # the same read in Thumb (a 32-bit T32 encoding)
    tbody = thumb(0xEE1D, 0x0F70, 0x4770)
    assert _mnems(tbody, True) == ["mrc", "bx"]
    with pytest.raises(ne.EmulationError, match="mrc executed"):
        ne.emulate_arm32_aapcs(tbody, [0, 0, 1], thumb=True)


@needs_uni
def test_emulate_arm32_conditional_machine_dependent_instruction_declines():
    """Verification round 1: an A32 mnemonic carries its condition (`mrceq`, `mrseq`), and the vetting matched the
    bare names only, so every CONDITIONAL coprocessor / status read ran: the thread pointer read back as 0 and
    `mrseq r0, apsr` as Unicorn's supervisor-mode CPSR, a value no user-mode device gives."""
    # cmp r2, r2 ; mrceq p15,0,r0,c13,c0,3 ; bx lr   (the condition holds, so the read executes)
    mrceq = arm(0xE1520002, 0x0E1D0F70, BX_LR)
    assert _mnems(mrceq) == ["cmp", "mrceq", "bx"]
    with pytest.raises(ne.EmulationError, match="mrceq executed"):
        ne.emulate_arm32_aapcs(mrceq, [0, 0, 1])
    # cmp r2, r2 ; mrseq r0, apsr ; bx lr
    mrseq = arm(0xE1520002, 0x010F0000, BX_LR)
    assert _mnems(mrseq) == ["cmp", "mrseq", "bx"]
    with pytest.raises(ne.EmulationError, match="mrseq executed"):
        ne.emulate_arm32_aapcs(mrseq, [0, 0, 1])
    # every name the set holds is matched whatever suffix the mnemonic carries
    assert ne._arm_insn_env(mrceq, 4, False) == "mrceq" and ne._arm_insn_env(mrseq, 4, False) == "mrseq"
    assert ne._arm_insn_env(mrceq, 0, False) == ""          # cmp is an ordinary instruction


@needs_uni
def test_emulate_arm32_without_a_return_declines():
    # mov r0, r2  -- no bx lr / pop pc: falling off the end is never read as a return
    with pytest.raises(ne.EmulationError, match="did not return"):
        ne.emulate_arm32_aapcs(arm(0xE1A00002), [0, 0, 1])


@needs_uni
def test_emulate_arm32_vfp_code_declines_with_the_engines_reason():
    # vmov s0, r2 ; vmov r0, s0 ; bx lr  -- the engine starts with the FPU off (as the gaps list says), so a
    # VFP instruction is an engine error, reported as one and never run past
    body = arm(0xEE002A10, 0xEE100A10, BX_LR)
    assert _disasm(body)[:2] == [("vmov", "s0, r2"), ("vmov", "r0, s0")]
    with pytest.raises(ne.EmulationError, match="unicorn error"):
        ne.emulate_arm32_aapcs(body, [0, 0, 7])


@needs_uni
def test_emulate_arm32_every_epilogue_that_reaches_the_caller_is_a_return():
    # push {lr} ; mov r0,#9 ; pop {pc}
    body = arm(0xE92D4000, 0xE3A00009, 0xE8BD8000)
    assert _mnems(body)[-1] in ("ldm", "pop")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0]) == 9
    # mov r0,#7 ; mov pc, lr   (the pre-interworking return)
    body = arm(0xE3A00007, 0xE1A0F00E)
    assert _disasm(body)[-1] == ("mov", "pc, lr")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0]) == 7
    # str lr,[sp,#-4]! ; mov r0,#7 ; ldr pc,[sp],#4   (capstone prints the post-indexed load as pop {pc})
    body = arm(0xE52DE004, 0xE3A00007, 0xE49DF004)
    assert _mnems(body)[0] == "str" and _mnems(body)[-1] in ("ldr", "pop")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0]) == 7
    # Thumb: push {lr} ; movs r0,#9 ; pop {pc}
    body = thumb(0xB500, 0x2009, 0xBD00)
    assert _disasm(body, True)[-1] == ("pop", "{pc}")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0], thumb=True) == 9


@needs_uni
def test_emulate_arm32_a_computed_jump_through_the_stack_is_not_a_return():
    """Verification round 1: every pop/ldm/ldr into PC was taken for the return and the run stopped before it, so
    this body read as 1 (r0 at the pop) where a device jumps on and returns x + 2."""
    # mov r0,#1 ; add r3,pc,#4 ; str r3,[sp,#-4]! (push {r3}) ; ldr pc,[sp],#4 (pop {pc}) ; add r0,r2,#2 ; bx lr
    body = arm(0xE3A00001, 0xE28F3004, 0xE52D3004, 0xE49DF004, 0xE2820002, BX_LR)
    assert _mnems(body) == ["mov", "add", "str", "pop", "add", "bx"]
    assert ne.emulate_arm32_aapcs(body, [0, 0, 7]) == 9
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0x40]) == 0x42


@needs_uni
def test_emulate_arm32_a_jump_table_runs_the_selected_case():
    """Verification round 1: `ldr pc, [table]` (a switch) was read as the return, so the function gave its
    selector (0, 1) where the code computes the case's value (0x11, 0x22)."""
    # add r1,pc,#20 (case0) ; add r3,r1,#8 (case1) ; push case1 ; push case0 ; mov r0,r2 ;
    # ldr pc,[sp,r0,lsl #2] ; nop ; case0: mov r0,#0x11 ; bx lr ; case1: mov r0,#0x22 ; bx lr
    body = arm(0xE28F1014, 0xE2813008, 0xE52D3004, 0xE52D1004, 0xE1A00002, 0xE79DF100, 0xE1A00000,
               0xE3A00011, BX_LR, 0xE3A00022, BX_LR)
    assert _disasm(body)[5] == ("ldr", "pc, [sp, r0, lsl #2]")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0]) == 0x11
    assert ne.emulate_arm32_aapcs(body, [0, 0, 1]) == 0x22
    # the compiler's position-independent form: add pc, pc, r2, lsl #3 ; nop ; case0 ; case1
    body = arm(0xE08FF182, 0xE1A00000, 0xE3A00011, BX_LR, 0xE3A00022, BX_LR)
    assert _disasm(body)[0] == ("add", "pc, pc, r2, lsl #3")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 0]) == 0x11
    assert ne.emulate_arm32_aapcs(body, [0, 0, 1]) == 0x22


@needs_uni
def test_emulate_arm32_a_result_that_depends_on_where_the_code_or_stack_sits_declines():
    """The load address and the stack pointer are the loader's and the thread's, not the bytes': the runs map the
    code and the stack at different addresses, so a value built from either differs. PC-relative data is the same
    at any base; an absolute address held in the bytes is unrelocated here, so it is valid at no base."""
    for word, text in ((0xE1A0000F, "r0, pc"), (0xE1A0000D, "r0, sp")):
        body = arm(word, BX_LR)
        assert _disasm(body)[0] == ("mov", text)
        with pytest.raises(ne.EmulationError, match="load address"):
            ne.emulate_arm32_aapcs(body, [0, 0, 1])
    assert len({r[3] for r in ne.ARM32_RUNS}) > 1 and len({r[4] for r in ne.ARM32_RUNS}) > 1
    # ldr r0,[pc,#0] ; bx lr ; .word 0x12345678  -- a literal pool inside the symbol reads the same anywhere
    body = arm(0xE59F0000, BX_LR, 0x12345678)
    assert _disasm(body)[0][0] == "ldr" and _disasm(body)[0][1].startswith("r0, [pc")
    assert ne.emulate_arm32_aapcs(body, [0, 0, 1]) == 0x12345678
    # a jump table of ABSOLUTE addresses, right for the first run's base only:
    # mov r0,r2 ; add r3,pc,#4 ; ldr pc,[r3,r0,lsl #2] ; pad ; .word case0, case1 ; case0 ; case1
    base = ne.ARM32_RUNS[0][3]
    body = arm(0xE1A00002, 0xE28F3004, 0xE793F100, 0, base + 0x18, base + 0x20,
               0xE3A00011, BX_LR, 0xE3A00022, BX_LR)
    assert _disasm(body)[2] == ("ldr", "pc, [r3, r0, lsl #2]")
    with pytest.raises(ne.EmulationError, match="fetch outside mapped code"):
        ne.emulate_arm32_aapcs(body, [0, 0, 0])


@needs_uni
def test_emulate_arm32_a_jump_to_a_fixed_address_is_never_the_return():
    """The return is a fetch at the CALLER'S return address, which differs run by run; a body that jumps to a
    constant (here the very canary one run uses) left the function in one run only, so it declines. On a device
    it faults: there is no value."""
    lr_a = ne.ARM32_RUNS[0][1]
    assert lr_a != ne.ARM32_RUNS[1][1]                       # the two canaries differ, or this proves nothing
    # mov r0,#7 ; ldr pc,[pc,#-4] ; .word <canary of run A>
    body = arm(0xE3A00007, 0xE51FF004, lr_a)
    assert _disasm(body)[1][0] == "ldr" and _disasm(body)[1][1].startswith("pc, [pc")
    with pytest.raises(ne.EmulationError, match="fetch outside mapped code"):
        ne.emulate_arm32_aapcs(body, [0, 0, 0])


@needs_uni
def test_emulate_arm32_an_instruction_set_switch_inside_the_body_declines():
    """Verification round 1: the body is vetted with the decoder of its entry instruction set, but `bx` can switch
    it. A32 entry, `add r3,pc,#1 ; bx r3`, then Thumb `mrc ; bx pc`, then A32 `bx lr` returned the fabricated
    thread pointer (the Thumb mrc decodes as an A32 svceq, so it was never vetted)."""
    body = arm(0xE28F3001, 0xE12FFF13) + thumb(0xEE1D, 0x0F70, 0x4778, 0x46C0) + arm(BX_LR)
    assert _mnems(body[:8]) == ["add", "bx"]
    assert _mnems(body[8:16], True) == ["mrc", "bx", "mov"]
    with pytest.raises(ne.EmulationError, match="instruction-set switch"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])
    # and the other way: Thumb entry, bx pc into A32 code
    body = thumb(0x4778, 0x46C0) + arm(0xE3A00007, BX_LR)
    assert _disasm(body[:4], True) == [("bx", "pc"), ("mov", "r8, r8")]
    with pytest.raises(ne.EmulationError, match="instruction-set switch"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1], thumb=True)


@needs_uni
@pytest.mark.parametrize("words,pair", [
    ((0x03A00001, 0x13A00002), ("moveq", "movne")),     # Z: the two complementary fills already differ
    ((0xA3A00001, 0xB3A00002), ("movge", "movlt")),     # N == V: the same under complementary fills
    ((0x83A00001, 0x93A00002), ("movhi", "movls")),     # C and not Z: likewise
])
def test_emulate_arm32_a_result_that_depends_on_the_entry_flags_declines(words, pair):
    """Verification round 1: the condition flags were whatever Unicorn starts with in every run, so a body
    conditional on the caller's flags gave one value; a device's flags are the caller's leftovers. The third
    fill is what separates GE/LT and HI/LS: with two complementary fills both runs agree on them."""
    body = arm(words[0], words[1], BX_LR)
    assert tuple(_mnems(body)[:2]) == pair
    with pytest.raises(ne.EmulationError, match="entry flags"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])


@needs_uni
def test_emulate_arm32_flags_the_body_sets_itself_are_defined():
    # cmp r2,#5 ; movlt r0,#1 ; movge r0,#2 ; bx lr  -- the flags are the body's own, so both legs resolve
    body = arm(0xE3520005, 0xB3A00001, 0xA3A00002, BX_LR)
    assert _mnems(body) == ["cmp", "movlt", "movge", "bx"]
    assert ne.emulate_arm32_aapcs(body, [0, 0, 3]) == 1
    assert ne.emulate_arm32_aapcs(body, [0, 0, 9]) == 2


@needs_uni
def test_emulate_arm32_the_return_address_is_undefined_to_the_body():
    # mov r0, lr ; bx lr  -- the caller's return address is no value the bytes give
    body = arm(0xE1A0000E, BX_LR)
    assert _disasm(body)[0] == ("mov", "r0, lr")
    with pytest.raises(ne.EmulationError, match="return address"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])
    # and no caller of the engine can pin it (it is the engine's return canary)
    with pytest.raises(ne.EmulationError, match="'lr' is the engine's"):
        ne.emulate_function(A32_DERIVE, ne.ARCH_ARM32, {"r2": 1, "lr": 0x1000}, "r0")


# ------------------------------------------------- verification round 2: every bit of the entry state, and more
def _both_values(vals, mask):
    """The bits of `mask` that are set in one of `vals` and clear in another."""
    ones = zeros = 0
    for v in vals:
        ones |= v
        zeros |= ~v
    return ones & zeros & mask


def test_arm32_runs_give_every_bit_of_the_entry_state_both_values():
    """Verification round 2: the runs differed in a few bits only (the LR canaries in bits 0, 12 and 20), so a body
    reading any other bit got one value. Over ARM32_RUNS every bit of every field is now set in one run and clear in
    another: all 64 of the register fill, all 32 of LR, N Z C V Q GE, bits 12..31 of the code base and 1..11 of the
    page offset (so 1..31 of a Thumb function's entry address, 2..31 of an A32 one), and bits 3..31 of the stack
    pointer."""
    fills, lrs, flags, bases, tops, offs = zip(*ne.ARM32_RUNS)
    assert _both_values(fills, ne.M64) == ne.M64
    assert _both_values(lrs, ne.M32) == ne.M32
    assert _both_values(flags, ne._APSR_MASK) == ne._APSR_MASK == 0xF80F0000
    assert _both_values(bases, 0xFFFFF000) == 0xFFFFF000
    assert _both_values(offs, 0xFFE) == 0xFFE
    assert _both_values([o & ~3 for o in offs], 0xFFC) == 0xFFC          # what an A32 body is given
    assert {o & 2 for o in offs} == {0, 2}                               # Thumb: both residues modulo 4
    assert _both_values(tops, 0xFFFFFFF8) == 0xFFFFFFF8
    for fill, lr, _flags, base, top, off in ne.ARM32_RUNS:
        assert base % 0x1000 == 0 and top % 8 == 0 and 0 <= off < 0x1000
        # the canary is never an address this run maps: not in the code's pages, not near the stack
        assert not base <= (lr & ~1) < base + ne._MAX_CODE + 0x2000
        assert not top - (1 << 24) <= (lr & ~1) <= top
        assert base + ne._MAX_CODE + 0x2000 <= 1 << 32
    assert any(lr & 1 for lr in lrs) and any(not lr & 3 for lr in lrs)   # a Thumb caller's and an A32 caller's


def _imm12(bit):
    """The canonical A32 modified-immediate encoding of 1 << bit (an 8-bit value rotated right by an even amount)."""
    if bit < 8:
        return 1 << bit
    imm8, base = (1, bit) if bit % 2 == 0 else (2, bit - 1)
    return (((32 - base) // 2) << 8) | imm8


def _bit_test(prefix, tst_word, bit):
    """`prefix` ; tst <reg>, #(1 << bit) ; moveq r0,#1 ; movne r0,#2 ; bx lr -- the encoding checked by capstone."""
    body = arm(*prefix, tst_word | _imm12(bit), 0x03A00001, 0x13A00002, BX_LR)
    mnem, ops = _disasm(body)[len(prefix)]
    assert mnem == "tst" and int(ops.split("#")[1], 0) & 0xFFFFFFFF == 1 << bit, (bit, mnem, ops)
    return body


@needs_uni
@pytest.mark.parametrize("what,prefix,tst_word,bits,undefined", [
    ("the return address", (), 0xE31E0000, range(32), False),              # tst lr, #bit
    ("the stack pointer", (), 0xE31D0000, range(3, 32), False),            # tst sp, #bit
    ("an undefined register", (), 0xE3110000, range(32), True),            # tst r1, #bit, r1 not set
], ids=["lr", "sp", "undefined-register"])
def test_emulate_arm32_a_result_that_reads_any_one_bit_of_the_entry_state_declines(what, prefix, tst_word, bits,
                                                                                    undefined):
    """Verification round 2, bit by bit: a test of ANY single bit of the caller's return address, the stack pointer
    or a register the caller did not set gives two answers over the runs. (The code address has no row: what an
    instruction reads as PC is the entry address plus its own offset, a sum, and a sum's bits are sampled by the
    three runs, not covered one by one. The engine's docstring and the build log say so.)"""
    plain = []
    for bit in bits:
        body = _bit_test(prefix, tst_word, bit)
        try:
            if undefined:
                got = ne.emulate_function(body, ne.ARCH_ARM32, {"r2": 1}, "r0")
            else:
                got = ne.emulate_arm32_aapcs(body, [0, 0, 1])
            plain.append((bit, got))
        except ne.EmulationError as e:
            assert "result depends on" in str(e), (what, bit, str(e))
    assert plain == [], "%s: these bits read plain: %r" % (what, plain)


@needs_uni
def test_emulate_arm32_the_high_bits_of_the_return_address_are_undefined():
    # the round 2 reproduction: lsr r0, lr, #24 ; bx lr read 0xFF (both canaries began 0xFF)
    body = arm(0xE1A00C2E, BX_LR)
    assert _disasm(body)[0] == ("lsr", "r0, lr, #0x18")
    with pytest.raises(ne.EmulationError, match="return address"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])


@needs_uni
def test_emulate_arm32_a_result_that_depends_on_the_entry_ge_flags_declines():
    """Round 2 survivor (_APSR_MASK narrowed to N Z C V): `sel` picks each result byte by a GE flag, and the GE flags
    are the caller's leftovers. With the fill dropped every run has GE = 0 and the body reads plain as its second
    operand."""
    body = arm(0xE6820FB1, BX_LR)
    assert _disasm(body)[0] == ("sel", "r0, r2, r1")
    with pytest.raises(ne.EmulationError, match="entry flags"):
        ne.emulate_arm32_aapcs(body, [0, 0x11111111, 0x22222222])
    tbody = thumb(0xFAA2, 0xF081, 0x4770)
    assert _disasm(tbody, True) == [("sel", "r0, r2, r1"), ("bx", "lr")]
    with pytest.raises(ne.EmulationError, match="entry flags"):
        ne.emulate_arm32_aapcs(tbody, [0, 0x11111111, 0x22222222], thumb=True)


# One encoding of every machine-dependent instruction name capstone prints, in A32 ...
A32_ENV = {
    "mrc": 0xEE1D0F70, "mrc2": 0xFE1D0F70, "mcr": 0xEE0D0F70, "mcr2": 0xFE0D0F70,
    "mrrc": 0xEC510F1E, "mrrc2": 0xFC510F1E, "mcrr": 0xEC410F1E, "mcrr2": 0xFC410F1E,
    "cdp": 0xEE000700, "cdp2": 0xFE000700,
    "ldc": 0xED905E00, "ldcl": 0xEDD05E00, "ldc2": 0xFD905E00, "ldc2l": 0xFDD05E00,
    "stc": 0xED805E00, "stcl": 0xEDC05E00, "stc2": 0xFD805E00, "stc2l": 0xFDC05E00,
    "mrs": 0xE10F0000, "msr": 0xE128F000, "vmrs": 0xEEF10A10, "vmsr": 0xEEE10A10,
    "cps": 0xF1020010, "cpsie": 0xF1080080, "cpsid": 0xF10C0080, "setend": 0xF1010200,
    "rfeia": 0xF8900A00, "rfeda": 0xF8100A00, "rfedb": 0xF9100A00, "rfeib": 0xF9900A00,
    "srsia": 0xF8CD0513, "srsda": 0xF84D0513, "srsdb": 0xF94D0513, "srsib": 0xF9CD0513,
    "smc": 0xE1600070, "hvc": 0xE1400070, "eret": 0xE160006E, "wfi": 0xE320F003, "wfe": 0xE320F002,
}
# ... and of every family in Thumb (the 16-bit forms where there is one)
T32_ENV = {
    "mrc": (0xEE1D, 0x0F70), "mrc2": (0xFE1D, 0x0F70), "mcr": (0xEE0D, 0x0F70), "mrrc": (0xEC51, 0x0F1E),
    "mcrr": (0xEC41, 0x0F1E), "cdp": (0xEE00, 0x0700), "ldc": (0xED90, 0x5E00), "stc": (0xED80, 0x5E00),
    "mrs": (0xF3EF, 0x8000), "msr": (0xF380, 0x8800), "vmrs": (0xEEF1, 0x0A10), "vmsr": (0xEEE1, 0x0A10),
    "cps": (0xF3AF, 0x8100), "cpsie": (0xB662,), "cpsid": (0xB672,), "setend": (0xB658,),
    "rfeia": (0xE990, 0xC000), "rfedb": (0xE810, 0xC000), "srsia": (0xE98D, 0xC013), "srsdb": (0xE80D, 0xC013),
    "smc": (0xF7F0, 0x8000), "hvc": (0xF7E0, 0x8000), "eret": (0xF3DE, 0x8F00), "wfi": (0xBF30,), "wfe": (0xBF20,),
}
# the two bare spellings capstone 5 never prints (it always names the addressing mode: rfeia, srsdb, ...)
ENV_NEVER_PRINTED = {"rfe", "srs"}


def _env_first(code, thumb_mode):
    """(mnemonic, condition-free instruction name) of the first instruction, as the vetting reads it."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    ins = next(Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb_mode else CS_MODE_ARM).disasm(code, 0))
    return ins.mnemonic, ins.insn_name()


@needs_uni
@pytest.mark.parametrize("name", sorted(A32_ENV))
def test_emulate_arm32_every_machine_dependent_instruction_declines_in_a32(name):
    """Round 2 survivor (ARM32_ENV_INSNS cut down to mrc and mrs left every test green): each name the set holds is
    an instruction the engine must not run. `mrrc p15,1,r0,r1,c14` unvetted returns Unicorn's live counter."""
    body = arm(A32_ENV[name], BX_LR)
    mnem, _base = _env_first(body, False)
    assert mnem == name
    with pytest.raises(ne.EmulationError, match="^%s executed" % name):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])


@needs_uni
@pytest.mark.parametrize("name", sorted(T32_ENV))
def test_emulate_arm32_every_machine_dependent_instruction_declines_in_thumb(name):
    body = thumb(*T32_ENV[name], 0x4770)
    mnem, _base = _env_first(body, True)
    assert mnem.split(".")[0] == name                         # capstone prints the wide hvc as hvc.w
    with pytest.raises(ne.EmulationError, match="^%s(\\.w)? executed" % name):
        ne.emulate_arm32_aapcs(body, [0, 0, 1], thumb=True)


def test_every_name_in_the_arm32_set_has_a_fixture_that_declines_on_it():
    """The two tests above cover the SET, not a sample of it: every name in ARM32_ENV_INSNS is the mnemonic or the
    instruction name of one of their fixtures, bar the two spellings capstone never prints. A name added to the set
    without an encoding here, or a capstone that starts printing `rfe`, fails this."""
    seen = set()
    for word in A32_ENV.values():
        seen.update(_env_first(arm(word), False))
    for halfwords in T32_ENV.values():
        seen.update(_env_first(thumb(*halfwords), True))
    assert ne.ARM32_ENV_INSNS - seen == ENV_NEVER_PRINTED
    assert set(A32_ENV) | set(T32_ENV) == ne.ARM32_ENV_INSNS - ENV_NEVER_PRINTED


@needs_uni
def test_emulate_arm32_a_decline_names_its_first_cause():
    """Round 2: inside a Thumb IT block the engine does not stop at once, so the body ran on to its return and the
    fetch there overwrote the reason: the conditional thread-pointer read was reported as a fetch outside the code."""
    # cmp r2, r2 ; it eq ; mrceq p15,0,r0,c13,c0,3 ; bx lr
    body = thumb(0x4292, 0xBF08, 0xEE1D, 0x0F70, 0x4770)
    assert _mnems(body, True) == ["cmp", "it", "mrceq", "bx"]
    with pytest.raises(ne.EmulationError, match="^mrc executed"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1], thumb=True)


@needs_uni
def test_emulate_arm32_runs_in_user_mode_so_an_exception_return_is_no_return(monkeypatch):
    """Round 2: Unicorn starts in supervisor mode, where `movs pc, lr` and `ldm sp!, {pc}^` jump to LR like any
    return, and both read 7. A JNI function runs in user mode, where they are UNPREDICTABLE (an undefined-instruction
    fault on the cores Android runs on): no value. Each is refused in EVERY run on its own, the first included (an
    A32 caller's return address, where supervisor mode returns cleanly), so this is the mode's doing and not a
    disagreement between the runs."""
    movs_pc = arm(0xE1A00002, 0xE1B0F00E)
    assert _disasm(movs_pc) == [("mov", "r0, r2"), ("movs", "pc, lr")]
    ldm_pc = arm(0xE92D4000, 0xE1A00002, 0xE8FD8000)
    assert _disasm(ldm_pc)[-1] == ("ldm", "sp!, {pc} ^")
    runs = ne.ARM32_RUNS
    assert len(runs) == 3
    for one in runs:
        monkeypatch.setattr(ne, "ARM32_RUNS", (one,))
        for body in (movs_pc, ldm_pc):
            with pytest.raises(ne.EmulationError, match="unicorn error"):
                ne.emulate_arm32_aapcs(body, [0, 0, 7])
        # the ordinary forms of the same two returns do return in this run (so the declines above are the S bit's)
        assert ne.emulate_arm32_aapcs(arm(0xE1A00002, 0xE1A0F00E), [0, 0, 7]) == 7
        assert ne.emulate_arm32_aapcs(arm(0xE92D4000, 0xE1A00002, 0xE8BD8000), [0, 0, 7]) == 7


@needs_uni
def test_emulate_arm32_where_the_function_sits_in_its_page_is_undefined():
    """The engine is handed the symbol's bytes, not its address, so the low twelve bits of a code address are no more
    in the bytes than the high twenty: the runs start the function at different offsets of its page."""
    # mov r0, pc ; and r0, r0, #0xff0 ; bx lr
    body = arm(0xE1A0000F, 0xE2000EFF, BX_LR)
    assert _disasm(body)[:2] == [("mov", "r0, pc"), ("and", "r0, r0, #0xff0")]
    with pytest.raises(ne.EmulationError, match="load address"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])
    # Thumb: mov r0, pc ; movs r3, #2 ; ands r0, r3 ; bx lr  -- whether the function starts at 0 or 2 modulo 4
    body = thumb(0x4678, 0x2302, 0x4018, 0x4770)
    assert _disasm(body, True)[:3] == [("mov", "r0, pc"), ("movs", "r3, #2"), ("ands", "r0, r3")]
    with pytest.raises(ne.EmulationError, match="load address"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1], thumb=True)


@needs_uni
def test_emulate_arm32_a_thumb_literal_load_declines_because_its_alignment_is_not_in_the_bytes():
    """A Thumb `ldr rX, [pc, #imm]` reads from Align(PC, 4), so the word it loads depends on whether the function
    starts at 0 or 2 modulo 4. Mapped at 0 only, a function the assembler laid out for 2 read a word made of the
    halves of two literals (0x6666CAFE for 0xCAFE0001): a wrong value, plain. With both residues in the runs it has
    two answers. (The A32 literal pool is word-aligned on every device and still reads: see the load-address test.)"""
    # as laid out for an entry at 2 modulo 4: ldr r0,[pc,#4] ; bx lr ; pad ; .word 0xCAFE0001 ; .word 0x55556666
    body = thumb(0x4801, 0x4770, 0x0000) + struct.pack("<II", 0xCAFE0001, 0x55556666)
    assert _disasm(body, True)[0] == ("ldr", "r0, [pc, #4]")
    with pytest.raises(ne.EmulationError, match="load address"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1], thumb=True)
    # and as laid out for an entry at 0 modulo 4
    body = thumb(0x4801, 0x4770) + struct.pack("<III", 0, 0x11112222, 0x33334444)
    with pytest.raises(ne.EmulationError, match="load address"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1], thumb=True)


@needs_uni
def test_emulate_arm32_only_the_symbols_own_bytes_execute():
    """The rest of the function's page is mapped (the code no longer starts it) but is not what a device has there:
    a jump into it is an error by name, never a slide through filler back into the body."""
    # b .+16 (past the end of the two-instruction body) ; bx lr
    body = arm(0xEA000002, BX_LR)
    assert _disasm(body)[0] == ("b", "#0x10")
    with pytest.raises(ne.EmulationError, match="execution left the symbol's bytes"):
        ne.emulate_arm32_aapcs(body, [0, 0, 1])


@needs_uni
def test_emulate_rejects_more_than_four_core_register_args():
    with pytest.raises(ne.EmulationError, match="more than 4"):
        ne.emulate_arm32_aapcs(A32_DERIVE, [1, 2, 3, 4, 5])


def test_emulate_function_rejects_an_unknown_arch():
    with pytest.raises(ne.EmulationError, match="unsupported arch"):
        ne.emulate_function(A32_DERIVE, "mips", {}, "r0")


# --------------------------------------------------------------------------- ELF .so builder
def arm32_so(funcs, thumb_names=(), machine=40, elf_class=1, endian="<", load_flags=None):
    """A minimal ELF ET_DYN (class `elf_class`: 1 = ELF32 as armeabi-v7a is; byte order `endian`) exporting
    `funcs` as sized FUNC symbols in a .text at vaddr 0x1000. Each entry is (name, code) or (name, code, opts)
    with opts {"bind": STB_*, "shndx": section index} (default GLOBAL in .text). A name in `thumb_names` gets its
    st_value's low bit set, as the toolchain marks a Thumb entry. `load_flags` None gives no program headers (the
    binder then reads the section headers alone); an int gives one PT_LOAD mapping .text with those p_flags (ELF32
    only), as every real library has. Deterministic; hand-built so the tests need no cross-assembler."""
    assert elf_class in (1, 2) and endian in ("<", ">")
    assert load_flags is None or elf_class == 1
    e = endian
    VADDR = 0x1000
    dynstr = b"\x00"
    offs = {}
    for f in funcs:
        if f[0] not in offs:
            offs[f[0]] = len(dynstr)
            dynstr += f[0].encode() + b"\x00"
    shstr = b"\x00"
    off_of = {}
    for s in (b".text", b".dynstr", b".dynsym", b".shstrtab"):
        off_of[s] = len(shstr)
        shstr += s + b"\x00"
    text = bytearray()
    addr = []
    for f in funcs:
        while len(text) % 4:
            text.append(0)
        addr.append(VADDR + len(text))
        text += f[1]
    if elf_class == 1:
        def sym(nm, val, size, info, shndx):
            return struct.pack(e + "IIIBBH", nm, val, size, info, 0, shndx)
        ent, ehsize, shentsize, phentsize = 16, 52, 40, 32
    else:
        def sym(nm, val, size, info, shndx):
            return struct.pack(e + "IBBHQQ", nm, info, 0, shndx, val, size)
        ent, ehsize, shentsize, phentsize = 24, 64, 64, 56
    dynsym = sym(0, 0, 0, 0, 0)
    for i, f in enumerate(funcs):
        opts = f[2] if len(f) > 2 else {}
        v = addr[i] | (1 if f[0] in thumb_names else 0)
        dynsym += sym(offs[f[0]], v, len(f[1]), (opts.get("bind", 1) << 4) | 2, opts.get("shndx", 1))
    phnum = 0 if load_flags is None else 1
    o = ehsize + phnum * phentsize
    text_off = o; o += len(text)
    dynstr_off = o; o += len(dynstr)
    dynsym_off = o; o += len(dynsym)
    shstr_off = o; o += len(shstr)
    while o % 8:
        o += 1
    shoff = o
    secs = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (off_of[b".text"], 1, 6, VADDR, text_off, len(text), 0, 0, 4, 0),
            (off_of[b".dynstr"], 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
            (off_of[b".dynsym"], 11, 0, 0, dynsym_off, len(dynsym), 2, 1, 4, ent),
            (off_of[b".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)]
    ident = b"\x7fELF" + bytes([elf_class, 1 if e == "<" else 2, 1, 0]) + b"\x00" * 8
    phdrs = b""
    if elf_class == 1:
        shdrs = b"".join(struct.pack(e + "IIIIIIIIII", *s) for s in secs)
        hdr = ident + struct.pack(e + "HHIIIIIHHHHHH", 3, machine, 1, 0, ehsize if phnum else 0, shoff, 0, ehsize,
                                  phentsize if phnum else 0, phnum, shentsize, len(secs), 4)
        if phnum:   # p_type PT_LOAD, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
            phdrs = struct.pack(e + "IIIIIIII", 1, text_off, VADDR, VADDR, len(text), len(text), load_flags, 4)
    else:
        shdrs = b"".join(struct.pack(e + "IIQQQQIIQQ", *s) for s in secs)
        hdr = ident + struct.pack(e + "HHIQQQIHHHHHH", 3, machine, 1, 0, 0, shoff, 0, ehsize, 0, 0, shentsize,
                                  len(secs), 4)
    blob = hdr + phdrs + bytes(text) + dynstr + dynsym + shstr
    return blob + b"\x00" * (shoff - len(blob)) + shdrs


NAME = jni_symbol("Lcom/h/N;", "derive")


def _defn(so, name=NAME):
    return [r[4] for r in dcc._SoBody(so).recs if r[0] == name]


# --------------------------------------------------------------------------- ELF32 .so parsing (_SoBody)
def test_sobody_reads_an_elf32_arm_func_as_the_runnable_a32_sentinel():
    body = dcc._SoBody(arm32_so([(NAME, A32_DERIVE)]))
    assert body.elf and body.elfclass == 1 and body.machine == dcc.EM_ARM
    assert _defn(arm32_so([(NAME, A32_DERIVE)])) == [(A32, A32_DERIVE)]
    # the sentinels are no e_machine (16-bit), and neither is the raw EM_ARM
    assert A32 > 0xFFFF and T32 > 0xFFFF and len({A32, T32, dcc.EM_ARM}) == 3


def test_sobody_routes_a_thumb_symbol_to_the_thumb_sentinel_with_a_masked_offset():
    # the SAME .so, but the symbol is marked Thumb (odd st_value): machine becomes the Thumb sentinel and the
    # bytes are still the function's (the low bit cleared before the address is mapped), not shifted by one.
    assert _defn(arm32_so([(NAME, A32_DERIVE)], thumb_names=[NAME])) == [(T32, A32_DERIVE)]


def test_sobody_keeps_the_raw_machine_for_an_arm_body_no_loader_loads():
    """Verification round 1: an ELF64 file with e_machine 40 and a big-endian ELF32 ARM file are libraries bionic
    refuses, so none of their code runs on a device. Their definitions keep the raw EM_ARM (never a runnable
    sentinel, Thumb bit or not), which every gate declines."""
    assert _defn(arm32_so([(NAME, A32_DERIVE)], elf_class=2)) == [(dcc.EM_ARM, A32_DERIVE)]
    assert _defn(arm32_so([(NAME, A32_DERIVE)], endian=">")) == [(dcc.EM_ARM, A32_DERIVE)]
    # ELF64 is as _parse_so reads it, so the binder's entry and the table's are the same definition
    so64 = arm32_so([(NAME, A32_DERIVE)], elf_class=2)
    assert dcc._parse_so(so64) == {NAME: (dcc.EM_ARM, A32_DERIVE)}
    odd = _defn(arm32_so([(NAME, A32_DERIVE), ("pad", A32_OTHER)], elf_class=2, thumb_names=[NAME]))
    assert odd == [(dcc.EM_ARM, (A32_DERIVE + A32_OTHER)[1:1 + len(A32_DERIVE)])]   # unmasked, as _parse_so maps it


def test_sobody_checks_the_pt_load_cover_at_the_thumb_masked_address():
    """A real armeabi-v7a library has program headers, and a sized FUNC is kept only when an executable PT_LOAD maps
    its bytes. For a Thumb symbol that cover is of the MASKED address: at the odd st_value the segment's bytes are
    the function's shifted by one (or run past the segment), and the definition would be dropped."""
    rx, r_only = 5, 4
    assert _defn(arm32_so([(NAME, A32_DERIVE)], load_flags=rx)) == [(A32, A32_DERIVE)]
    assert _defn(arm32_so([(NAME, T32_DERIVE)], thumb_names=[NAME], load_flags=rx)) == [(T32, T32_DERIVE)]
    # not last in the segment either (the unmasked range would still be inside it, with shifted bytes)
    two = arm32_so([(NAME, T32_DERIVE), ("pad", A32_OTHER)], thumb_names=[NAME], load_flags=rx)
    assert _defn(two) == [(T32, T32_DERIVE)]
    # code in a segment without PF_X faults on a device: no definition, so nothing binds
    assert _defn(arm32_so([(NAME, A32_DERIVE)], load_flags=r_only)) == [None]
    assert _defn(arm32_so([(NAME, T32_DERIVE)], thumb_names=[NAME], load_flags=r_only)) == [None]


# --------------------------------------------------------------------------- the table fold-in (_fold_arm32)
def _table(*sos, pre=None):
    table = dcc._NativeTable(pre or {})
    dcc._fold_arm32(table, dcc._SoBodies(sos))
    return dict(table)


def test_fold_adds_only_an_export_a_loader_could_return():
    """A LOCAL static and an undefined reference are no binding of the method (dlsym returns neither); folded in,
    one would also shadow the real export of the same name that follows it."""
    assert _table(arm32_so([(NAME, A32_DERIVE)])) == {NAME: (A32, A32_DERIVE)}
    assert _table(arm32_so([(NAME, A32_DERIVE)], thumb_names=[NAME])) == {NAME: (T32, A32_DERIVE)}
    assert _table(arm32_so([(NAME, A32_DERIVE, {"bind": 2})])) == {NAME: (A32, A32_DERIVE)}        # WEAK
    assert _table(arm32_so([(NAME, A32_DERIVE, {"bind": 0})])) == {}                               # LOCAL
    assert _table(arm32_so([(NAME, A32_DERIVE, {"shndx": 0})])) == {}                              # undefined
    # a LOCAL decoy ahead of the GLOBAL export of the same name: the export is the table's
    so = arm32_so([(NAME, A32_OTHER, {"bind": 0}), (NAME, A32_DERIVE)])
    assert _table(so) == {NAME: (A32, A32_DERIVE)}


def test_fold_keeps_a_64_bit_binding_and_the_first_arm32_body():
    held = (dcc.EM_AARCH64, A64_DERIVE)
    assert _table(arm32_so([(NAME, A32_DERIVE)]), pre={NAME: held}) == {NAME: held}
    first, second = arm32_so([(NAME, A32_DERIVE)]), arm32_so([(NAME, A32_OTHER)])
    assert _table(first, second) == {NAME: (A32, A32_DERIVE)}
    assert _table(second, first) == {NAME: (A32, A32_OTHER)}


def test_fold_takes_elf32_arm_bodies_only_and_keeps_an_unloadable_one_raw():
    # big-endian ELF32 ARM: folded with the RAW machine, so the call declines by name at the invoke gate
    assert _table(arm32_so([(NAME, A32_DERIVE)], endian=">")) == {NAME: (dcc.EM_ARM, A32_DERIVE)}
    # an ELF64 body is _parse_so's to read (never this fold's), and an ELF32 body of another machine is not ARM
    assert _table(arm32_so([(NAME, A32_DERIVE)], elf_class=2)) == {}
    assert _table(arm32_so([(NAME, A32_DERIVE)], machine=3)) == {}


# --------------------------------------------------------------------------- dispatch (_native_dispatch)
@needs_uni
def test_native_dispatch_resolves_arm32_and_thumb():
    # ABI order [JNIEnv, jclass, arg] -> r0, r1, r2
    assert dcc._native_dispatch(A32_DERIVE, [None, None, 7], A32) == derive(7)
    assert dcc._native_dispatch(T32_DERIVE, [None, None, 12], T32) == tderive(12)


def test_native_dispatch_declines_the_raw_arm_machine_and_any_other():
    """The raw EM_ARM is a definition out of a container no loader loads; it and every other machine without an
    emulator decline in the dispatcher itself, which used to hand any non-x86 machine's bytes to the AArch64
    reader. The bytes here ARE valid AArch64 (`add w0, w2, #7 ; ret`), so without the guard they give a value."""
    for mach in (dcc.EM_ARM, 3, 243):
        with pytest.raises(dcc._Decline, match="not modelled"):
            dcc._native_dispatch(A64_DERIVE, [None, None, 5], mach)


@needs_uni
def test_native_dispatch_fails_closed_when_the_body_reads_the_jnienv():
    # add r0, r2, r0 ; bx lr  -- r0 is the (undefined) JNIEnv pointer: the value depends on it, so decline
    body = arm(0xE0820000, BX_LR)
    assert _disasm(body)[0] == ("add", "r0, r2, r0")
    with pytest.raises(dcc._Decline, match="undefined register"):
        dcc._native_dispatch(body, [None, None, 3], A32)


@needs_uni
def test_native_dispatch_cross_checks_device_like_pointers():
    """A body that tests a property of the JNIEnv pointer EVERY poison fill shares agrees with itself in every
    poison run; only the run with device-like pointers shows that the value hangs on the pointer. Since round 2 no
    single bit is such a property (each takes both values over the fills), so this one is of two bytes: every fill
    repeats one byte, and no pointer does."""
    # eor r3, r0, r0, lsr #8 ; tst r3, #0xff ; moveq r0,#1 ; movne r0,#2 ; bx lr   (are bytes 0 and 1 equal?)
    body = arm(0xE0203420, 0xE31300FF, 0x03A00001, 0x13A00002, BX_LR)
    assert _disasm(body)[:2] == [("eor", "r3, r0, r0, lsr #8"), ("tst", "r3, #0xff")]
    assert all((run[0] ^ (run[0] >> 8)) & 0xFF == 0 for run in ne.ARM32_RUNS)     # every poison shares the property
    for mach in (A32, T32):
        env = dcc._DEVICE_ARGS[mach][0]
        assert (env ^ (env >> 8)) & 0xFF                                          # the device-like JNIEnv does not
    assert dcc._unicorn_value(body, [None, None, 3], A32) == 1                    # so the engine alone answers 1
    with pytest.raises(dcc._Decline, match="device-like pointers"):
        dcc._native_dispatch(body, [None, None, 3], A32)


@needs_uni
def test_native_dispatch_maps_two_java_ints_and_declines_a_third():
    """Round 2 survivor (`r4` added to the AAPCS32 argument registers): JNIEnv, jclass and two Java ints fill
    r0..r3; a third Java int is on the stack, which no reader here models, so the call declines by name. With `r4`
    taken for it the body below (it reads r2 and r3 alone) gave a value."""
    body = arm(0xE0820003, BX_LR)
    assert _disasm(body)[0] == ("add", "r0, r2, r3")
    assert dcc._native_dispatch(body, [None, None, 3, 4], A32) == 7
    with pytest.raises(dcc._Decline, match="stack arguments are not modelled"):
        dcc._native_dispatch(body, [None, None, 3, 4, 5], A32)
    tbody = thumb(0x18D0, 0x4770)
    assert _disasm(tbody, True) == [("adds", "r0, r2, r3"), ("bx", "lr")]
    assert dcc._native_dispatch(tbody, [None, None, 3, 4], T32) == 7
    with pytest.raises(dcc._Decline, match="stack arguments are not modelled"):
        dcc._native_dispatch(tbody, [None, None, 3, 4, 5], T32)


@needs_uni
def test_native_dispatch_interprets_thumb_bytes_in_thumb_mode_only():
    # The Thumb body decoded as A32 must NOT yield the Thumb value: a wrong mode is never a quiet wrong answer.
    try:
        as_arm = dcc._native_dispatch(T32_DERIVE, [None, None, 12], A32)
    except dcc._Decline:
        as_arm = None
    assert as_arm != tderive(12)


def test_arm32_declines_by_name_when_the_unicorn_engine_is_unavailable(monkeypatch):
    monkeypatch.setattr(ne, "UNICORN_AVAILABLE", False)
    monkeypatch.setattr(ne, "UNICORN_UNAVAILABLE_REASON", "test: engine switched off")
    with pytest.raises(dcc._Decline, match="needs the Unicorn engine, which is unavailable: test: engine switched"):
        dcc._arm32_dispatch(A32_DERIVE, [None, None, 1], A32)


# --------------------------------------------------------------------------- end to end (codes_in_dex_ex)
N_CLS, REL_CLS = "Lcom/h/N;", "Lcom/h/Release;"


def _hex_tail(d, a):
    """Append 'ANS-' + the 16 hex digits of the long in v0:v1 and return the string (the chain's ending)."""
    a.op("new-instance", 2, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [2])
    a.op("const-string", 3, d.s("ANS-")).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 3])
    a.op("const-string", 3, d.s("0123456789ABCDEF")).op("const/16", 4, 60)
    a.label("hex")
    a.op("ushr-long", 6, 0, 4).op("long-to-int", 8, 6).op("and-int/lit8", 8, 8, 15)
    a.op("invoke-virtual", d.m(STR, "charAt", "C", ["I"]), [3, 8]).op("move-result", 9)
    a.op("invoke-virtual", d.m(SB, "append", SB, ["C"]), [2, 9])
    a.op("add-int/lit8", 4, 4, -4).op("if-gez", 4, "hex")
    a.op("invoke-virtual", d.m(SB, "toString", STR), [2]).op("move-result-object", 2).op("return-object", 2)


def native_chain_dex(seed_a, seed_b):
    """A dex whose Release.code() builds 'ANS-' + 16 hex from two calls of a `static native int derive(int)` (the
    method has no dex body: the VM binds it from the .so). The two 32-bit returns are the high and low halves of
    the 64-bit code."""
    assert 0 <= seed_a < 0x7000 and 0 <= seed_b < 0x7000     # const/16, and small enough that no return is negative
    d = DexWriter()
    d.cls(N_CLS)
    d.cls(REL_CLS)
    nat = d.method(N_CLS, "derive", "I", ["I"], None, flags=ACC_PUBLIC | ACC_STATIC | ACC_NATIVE)
    a = Asm()
    a.op("const/16", 3, seed_a)
    a.op("invoke-static", nat, [3]).op("move-result", 3)
    a.op("int-to-long", 0, 3)
    a.op("const/16", 10, 32).op("shl-long", 0, 0, 10)
    a.op("const/16", 3, seed_b)
    a.op("invoke-static", nat, [3]).op("move-result", 3)
    a.op("int-to-long", 4, 3)                    # sign-extends: the seeds keep both returns positive
    a.op("or-long", 0, 0, 4)
    _hex_tail(d, a)
    d.method(REL_CLS, "code", STR, [], a.finish(), regs=11)
    return d.build()


def wide_chain_dex(ret, param):
    """A dex whose Release.code() calls a `static native <ret> derive(<param>)` once, where ret and param are 'I' or
    'J', and prints the result: the shapes the arm32 invoke gate declines before any emulation."""
    d = DexWriter()
    d.cls(N_CLS)
    d.cls(REL_CLS)
    nat = d.method(N_CLS, "derive", ret, [param], None, flags=ACC_PUBLIC | ACC_STATIC | ACC_NATIVE)
    a = Asm()
    a.op("const-wide", 0, 0x1234)
    a.op("invoke-static", nat, [0, 1] if param == "J" else [0])
    if ret == "J":
        a.op("move-result-wide", 0)
    else:
        a.op("move-result", 3).op("int-to-long", 0, 3)
    _hex_tail(d, a)
    d.method(REL_CLS, "code", STR, [], a.finish(), regs=11)
    return d.build()


def ints_chain_dex(count):
    """A dex whose Release.code() calls a `static native int derive(int, ...)` of `count` int parameters (5, 6, 7,
    ...) once and prints the result."""
    d = DexWriter()
    d.cls(N_CLS)
    d.cls(REL_CLS)
    nat = d.method(N_CLS, "derive", "I", ["I"] * count, None, flags=ACC_PUBLIC | ACC_STATIC | ACC_NATIVE)
    a = Asm()
    regs = list(range(3, 3 + count))
    for i, r in enumerate(regs):
        a.op("const/16", r, 5 + i)
    a.op("invoke-static", nat, regs).op("move-result", 3).op("int-to-long", 0, 3)
    _hex_tail(d, a)
    d.method(REL_CLS, "code", STR, [], a.finish(), regs=11)
    return d.build()


SA, SB_ = 0x111, 0x2222


def _derive_midx(dex):
    """The method id of the chain's native `derive` in a parsed Dex."""
    return next(i for i in range(dex.meth_size) if dex.meth(i) == (N_CLS, "derive"))


def want(fn, sa=SA, sb=SB_):
    return "ANS-%016X" % ((fn(sa) << 32) | fn(sb))


def run_chain(dex, sos):
    trace = []
    codes, declines = dcc.codes_in_dex_ex(dex, sos, _trace=trace)
    return codes, declines, [e.get("reason") or "" for e in trace]


def assert_declined(dex, sos, reason):
    codes, declines, reasons = run_chain(dex, sos)
    assert codes == [] and declines == 1, (codes, declines, reasons)
    assert any(reason in r for r in reasons), reasons


@needs_uni
def test_chain_reads_an_arm32_native_code_plain():
    codes, declines, reasons = run_chain(native_chain_dex(SA, SB_), [arm32_so([(NAME, A32_DERIVE)])])
    assert codes == [want(derive)] and declines == 0, reasons


@needs_uni
def test_chain_reads_a_thumb_native_code_plain():
    so = arm32_so([(NAME, T32_DERIVE)], thumb_names=[NAME])   # same symbol, Thumb entry
    codes, declines, reasons = run_chain(native_chain_dex(0x33, 0x4444), [so])
    assert codes == [want(tderive, 0x33, 0x4444)] and declines == 0, reasons


@needs_uni
def test_chain_reads_a_library_with_program_headers_and_declines_a_non_executable_one():
    """What a real armeabi-v7a library looks like: an executable PT_LOAD over the code (the Thumb cover is of the
    masked address). Code a segment without PF_X holds faults on a device, so it gives no code."""
    dex = native_chain_dex(SA, SB_)
    codes, declines, reasons = run_chain(dex, [arm32_so([(NAME, A32_DERIVE)], load_flags=5)])
    assert codes == [want(derive)] and declines == 0, reasons
    so = arm32_so([(NAME, T32_DERIVE), ("pad", A32_OTHER)], thumb_names=[NAME], load_flags=5)
    codes, declines, reasons = run_chain(dex, [so])
    assert codes == [want(tderive)] and declines == 0, reasons
    for so in (arm32_so([(NAME, A32_DERIVE)], load_flags=4),
               arm32_so([(NAME, T32_DERIVE)], thumb_names=[NAME], load_flags=4)):
        codes, declines, reasons = run_chain(dex, [so])
        assert codes == [] and declines == 1, reasons


@needs_uni
def test_chain_binds_the_export_not_a_local_static_of_the_same_name():
    # a LOCAL decoy ahead of the GLOBAL export: a device's dlsym returns the export, and so does the chain
    so = arm32_so([(NAME, A32_OTHER, {"bind": 0}), (NAME, A32_DERIVE)])
    codes, declines, reasons = run_chain(native_chain_dex(SA, SB_), [so])
    assert codes == [want(derive)] and declines == 0, reasons
    # a LOCAL symbol alone is no binding at all
    codes, declines, reasons = run_chain(native_chain_dex(SA, SB_), [arm32_so([(NAME, A32_DERIVE, {"bind": 0})])])
    assert codes == [] and declines == 1, reasons


@needs_uni
def test_chain_declines_a_conditional_thread_pointer_read():
    """Verification round 1, end to end: cmp r2,r2 ; mrceq (thread pointer) ; add r0,r0,r2 ; bx lr read plain."""
    body = arm(0xE1520002, 0x0E1D0F70, 0xE0800002, BX_LR)
    assert _mnems(body) == ["cmp", "mrceq", "add", "bx"]
    assert_declined(native_chain_dex(SA, SB_), [arm32_so([(NAME, body)])], "mrceq executed")


@needs_uni
def test_chain_runs_a_computed_jump_to_the_value_a_device_computes():
    # mov r0,#1 ; add r3,pc,#4 ; push {r3} ; pop {pc} ; add r0,r2,#2 ; bx lr  -- x + 2, never the 1 at the pop
    body = arm(0xE3A00001, 0xE28F3004, 0xE52D3004, 0xE49DF004, 0xE2820002, BX_LR)
    codes, declines, reasons = run_chain(native_chain_dex(SA, SB_), [arm32_so([(NAME, body)])])
    assert codes == [want(other)] and declines == 0, reasons


@needs_uni
def test_chain_declines_a_jlong_argument_native_on_arm32():
    # (J)I: a jlong argument uses an even-aligned register pair the 1-register mapping cannot place
    assert_declined(wide_chain_dex("I", "J"), [arm32_so([(NAME, A32_DERIVE)])], "arm32 jlong argument")


@needs_uni
def test_chain_declines_a_jlong_return_native_on_arm32():
    # (I)J: a jlong return comes back in r0:r1, and r0 alone is half of it
    assert_declined(wide_chain_dex("J", "I"), [arm32_so([(NAME, A32_DERIVE)])], "arm32 jlong return")


@needs_uni
def test_chain_declines_an_arm32_native_whose_proto_does_not_read():
    """Without the method's shorty the argument widths are unknown, and the x86/arm64 fallback (one register per
    Dalvik slot) would put a jlong in one 32-bit register: the arm32 native declines by name."""
    dex = dcc.Dex(native_chain_dex(SA, SB_))
    assert dex.meth_shorty(_derive_midx(dex)) == "II"
    dex.proto_off = 0                                        # as a dex without a proto section reads
    assert_declined(dex, [arm32_so([(NAME, A32_DERIVE)])], "arm32 native needs the method proto")


@needs_uni
def test_chain_maps_two_java_ints_and_declines_a_third_on_arm32():
    """Round 2: the stack-argument limit through the chain. (II)I fills r2 and r3 and reads plain; (III)I has its
    third int on the stack and declines by name, though this body never reads it."""
    so = arm32_so([(NAME, arm(0xE0820003, BX_LR))])              # add r0, r2, r3 ; bx lr
    codes, declines, reasons = run_chain(ints_chain_dex(2), [so])
    assert codes == ["ANS-%016X" % (5 + 6)] and declines == 0, reasons
    assert_declined(ints_chain_dex(3), [so], "stack arguments are not modelled")


@needs_uni
def test_chain_declines_a_body_that_reads_bits_of_the_entry_state_the_runs_used_to_share():
    """Round 2, the two reproductions through codes_in_dex_ex (both read plain, with no decline)."""
    # lsr r0, lr, #24 ; bx lr  read ANS-000000FF000000FF
    assert_declined(native_chain_dex(SA, SB_), [arm32_so([(NAME, arm(0xE1A00C2E, BX_LR))])], "return address")
    # tst r0, #1 << 26 ; moveq r0,#1 ; movne r0,#2 ; bx lr  (r0 is the JNIEnv) read ANS-0000000200000002
    body = arm(0xE3100301, 0x03A00001, 0x13A00002, BX_LR)
    assert _disasm(body)[0] == ("tst", "r0, #0x4000000")
    assert_declined(native_chain_dex(SA, SB_), [arm32_so([(NAME, body)])], "undefined register")


@needs_uni
def test_chain_declines_an_arm32_native_that_returns_the_denied_sentinel():
    """Round 2 decision: the x86-64 rule (a native returning 0 is the gate-fail leg, whose chain assembles a decoy)
    holds on the 32-bit ARM path too. A returned 0 is a decline in A32 and in Thumb, never ANS-0000000000000000."""
    body = arm(0xE3A00000, BX_LR)
    assert _disasm(body)[0] == ("mov", "r0, #0")
    assert_declined(native_chain_dex(SA, SB_), [arm32_so([(NAME, body)])],
                    "arm32 native returned the denied sentinel 0")
    tbody = thumb(0x2000, 0x4770)
    assert _disasm(tbody, True) == [("movs", "r0, #0"), ("bx", "lr")]
    assert_declined(native_chain_dex(SA, SB_), [arm32_so([(NAME, tbody)], thumb_names=[NAME])],
                    "arm32 native returned the denied sentinel 0")


def test_chain_declines_an_arm_definition_from_a_container_no_loader_loads():
    """Verification round 1 (the Day 25 critical guard's shape): an ELF64 file with e_machine 40 and a big-endian
    ELF32 ARM file both read plain. bionic loads neither, so no library code runs on a device: both decline, by
    name, before any emulation (so this holds with or without the engine)."""
    dex = native_chain_dex(SA, SB_)
    assert_declined(dex, [arm32_so([(NAME, A32_DERIVE)], elf_class=2)], "container no Android loader loads")
    assert_declined(dex, [arm32_so([(NAME, A32_DERIVE)], endian=">")], "container no Android loader loads")


@needs_uni
def test_chain_keeps_the_64_bit_binding_beside_an_arm32_body_of_the_same_name():
    """arm64-v8a beside armeabi-v7a, the two computing differently: the 64-bit body answers (SO_ELF32_LEGS
    'ignore', as before this item), in either delivery order; the arm32 body never replaces it."""
    so64 = arm32_so([(NAME, A64_DERIVE)], machine=dcc.EM_AARCH64, elf_class=2)
    so32 = arm32_so([(NAME, A32_DERIVE)])
    assert derive64(SA) != derive(SA)
    for sos in ([so64, so32], [so32, so64]):
        codes, declines, reasons = run_chain(native_chain_dex(SA, SB_), sos)
        assert codes == [want(derive64)] and declines == 0, reasons


@needs_uni
def test_chain_declines_two_arm32_bodies_that_define_the_native_differently():
    # armeabi beside armeabi-v7a with other code: which one the device loads is not in the bytes
    a, b = arm32_so([(NAME, A32_DERIVE)]), arm32_so([(NAME, A32_OTHER)])
    for sos in ([a, b], [b, a]):
        assert_declined(native_chain_dex(SA, SB_), sos, "so-ambig")
    # the same definition twice (two splits carrying one library) is one binding
    codes, declines, reasons = run_chain(native_chain_dex(SA, SB_), [a, arm32_so([(NAME, A32_DERIVE), ("x", A32_OTHER)])])
    assert codes == [want(derive)] and declines == 0, reasons


def _verdict(so):
    """so-ambig's verdict (the KB-2 bridge's question) on the chain's native call over the table of one library."""
    dex = dcc.Dex(native_chain_dex(SA, SB_))
    bodies = dcc._SoBodies([so])
    table = dcc._NativeTable()
    for sob in bodies:
        table.update(bodies.body(sob).funcs)
    dcc._fold_arm32(table, bodies)
    table.so_view = dcc._SoView(bodies.distinct)
    table.dexes = [dex]
    return dcc._so_verdict(dcc.VM(dex, table, {}), _derive_midx(dex))


def test_so_verdict_binds_a_vetted_arm32_definition_and_refuses_the_raw_machine():
    assert _verdict(arm32_so([(NAME, A32_DERIVE)])) == ("bind", frozenset([(A32, A32_DERIVE)]))
    assert _verdict(arm32_so([(NAME, T32_DERIVE)], thumb_names=[NAME])) == ("bind", frozenset([(T32, T32_DERIVE)]))
    got = _verdict(arm32_so([(NAME, A32_DERIVE)], elf_class=2))
    assert got[0] == "hard" and "machine-40" in got[1]
    got = _verdict(arm32_so([(NAME, A32_DERIVE)], endian=">"))
    assert got[0] == "hard" and "machine-40" in got[1]


# --------------------------------------------------------------------------- the spec's other named paths
def _members(blob):
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


@needs_uni
@pytest.mark.parametrize("what,blob,code", [
    ("a branching (gated) x86-64 native", lambda: MS.fixture("d25_set6_native.apk"),
     lambda: MS.truths()["d25_set6"]["answer"]),
    ("a straight-line native in a bundled .so", lambda: MS.fixture("d23_set5_native.apk"),
     lambda: MS.truths()["d23_set5"]["answer"]),
    ("reflection", lambda: MS.fixture("d25_set7_reflection.apk"), lambda: MS.truths()["d25_set7"]["answer"]),
    ("a secondary dex loaded in memory and invoked by reflection", lambda: MF.loader_apk(),
     lambda: MF.loader_value(*MF.LOADER_BASE)),
    ("a dex chain through a table", lambda: MF.chain_apk(MF.CHAIN_BASE), lambda: MF.chain_value(*MF.CHAIN_BASE)),
])
def test_the_specs_other_named_paths_resolve_on_their_synthetic_probe(what, blob, code):
    """The spec names secondary dex, dex-chain execution, branching native x86-64, reflection and native .so as the
    codecs the shipped search could not compute. Each was already modelled when this item started (B-229 and the
    import); this is the probe that says so: every one reads its synthetic build to the code its builder computed,
    with no decline, so none of them is the gap this item had to widen (32-bit ARM was)."""
    trace = []
    codes, declines = dcc.analysis_codes_ex(_members(blob()), _trace=trace)
    assert (codes, declines) == ([code()], 0), (what, trace)
    assert [e["outcome"] for e in trace] == ["code"], (what, trace)
