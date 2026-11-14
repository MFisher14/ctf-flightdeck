"""B-165: the custom-VM lifter scaffold (solvers/binary/vm_lifter.py).

A tiny 16-bit stack VM is defined inside the test; the scaffold must decode it, lift it to a
readable listing, and run the agent's handlers to a known output -- and must fail loudly on an
unknown opcode, a truncated operand, a bad pc, and a runaway loop.
"""
from __future__ import annotations

import pytest

import vm_lifter as vl


def _spec(handlers=None):
    opcodes = {
        0x00: vl.VMOp("halt", ir="halt"),
        0x01: vl.VMOp("push", (vl.Operand("imm", 2),), ir="push {0}"),
        0x02: vl.VMOp("add", ir="add"),
        0x03: vl.VMOp("out", ir="out"),
        0x04: vl.VMOp("jmp", (vl.Operand("addr", 2),), ir="jmp {0}"),
        0x05: vl.VMOp("pushb", (vl.Operand("imm", 1, signed=True),)),   # no ir template
    }
    return vl.VMSpec(opcodes=opcodes, handlers=handlers or {})


# 01 41 00 | 01 01 00 | 02 | 03 | 00  ->  push 0x41, push 1, add, out, halt
_PROG = bytes.fromhex("014100010100020300")


def test_disassemble_decodes_the_sequence():
    insns = vl.disassemble(_PROG, _spec())
    assert [i.name for i in insns] == ["push", "push", "add", "out", "halt"]
    assert insns[0].operands == (0x41,) and insns[0].size == 3
    assert insns[2].offset == 6 and insns[2].size == 1


def test_lift_renders_ir_template_and_falls_back():
    insns = vl.disassemble(_PROG, _spec())
    lines = vl.lift(insns, _spec())
    assert lines[0].text == "push 65"
    assert lines[2].text == "add"
    # default rendering (no ir template) for pushb -0x10
    pb = vl.disassemble(b"\x05\xf0", _spec())
    assert pb[0].operands == (-16,)
    assert vl.lift(pb, _spec())[0].text == "pushb -16"


def test_interpret_runs_handlers_to_known_output():
    def h_push(st, ops):
        st.stack.append(ops[0])

    def h_add(st, ops):
        b, a = st.stack.pop(), st.stack.pop()
        st.stack.append((a + b) & 0xFFFF)

    def h_out(st, ops):
        st.output.append(st.stack.pop() & 0xFF)

    def h_halt(st, ops):
        st.halted = True

    spec = _spec({"push": h_push, "add": h_add, "out": h_out, "halt": h_halt})
    state = vl.interpret(vl.disassemble(_PROG, spec), spec)
    assert bytes(state.output) == b"B"          # 0x41 + 1 = 0x42
    assert state.halted and state.stack == []


def test_unknown_opcode_and_truncation_raise():
    with pytest.raises(vl.VMDecodeError, match="unknown opcode 0xff"):
        vl.disassemble(b"\xff", _spec())
    with pytest.raises(vl.VMDecodeError, match="truncated operand"):
        vl.disassemble(b"\x01\x41", _spec())          # push needs 2 operand bytes, only 1 given
    wide = vl.VMSpec(opcodes={0x0001: vl.VMOp("nop")}, opcode_size=2)
    with pytest.raises(vl.VMDecodeError, match="truncated opcode"):
        vl.disassemble(b"\x00", wide)                 # a 2-byte opcode field, only 1 byte present


def test_disassemble_past_end_is_empty():
    assert vl.disassemble(b"\x01\x41\x00", _spec(), start=3) == []   # nothing to decode, no error


def test_negative_start_or_count_is_refused_not_decoded_from_the_end():
    # data[-1:] would decode the trailing byte as a bogus instruction at offset -1
    with pytest.raises(vl.VMDecodeError, match="negative"):
        vl.disassemble(b"\x01\x00", _spec(), start=-1)
    with pytest.raises(vl.VMDecodeError, match="negative"):
        vl.disassemble(_PROG, _spec(), start=-3)
    with pytest.raises(vl.VMDecodeError, match="negative"):
        vl.disassemble(_PROG, _spec(), count=-1)
    assert [i.offset for i in vl.disassemble(_PROG, _spec(), start=0, count=1)] == [0]


def test_interpret_caps_infinite_loops():
    def h_jmp(st, ops):
        st.pc = ops[0]

    spec = _spec({"jmp": h_jmp})
    insns = vl.disassemble(b"\x04\x00\x00", spec)       # jmp 0 -> spins
    with pytest.raises(vl.VMRuntimeError, match="exceeded 50 steps"):
        vl.interpret(insns, spec, max_steps=50)


def _full_handlers(extra=None):
    def h_push(st, ops):
        st.stack.append(ops[0])

    def h_add(st, ops):
        b, a = st.stack.pop(), st.stack.pop()
        st.stack.append((a + b) & 0xFFFF)

    def h_out(st, ops):
        st.output.append(st.stack.pop() & 0xFF)

    def h_halt(st, ops):
        st.halted = True

    return {"push": h_push, "add": h_add, "out": h_out, "halt": h_halt, **(extra or {})}


def test_step_cap_boundary_is_exact():
    spec = _spec(_full_handlers())
    insns = vl.disassemble(_PROG, spec)                 # exactly 5 instructions run, halt included
    st = vl.interpret(insns, spec, max_steps=5)
    assert st.steps == 5 and bytes(st.output) == b"B"
    with pytest.raises(vl.VMRuntimeError, match="exceeded 4 steps"):
        vl.interpret(insns, spec, max_steps=4)


def test_a_passed_state_resumes_from_its_pc_and_input():
    # "in" reads one input byte; "halt" pauses the machine; the second call must continue after it
    def h_in(st, ops):
        st.stack.append(st.input[st.input_pos])
        st.input_pos += 1

    opcodes = dict(_spec().opcodes)
    opcodes[0x06] = vl.VMOp("in")
    spec = vl.VMSpec(opcodes=opcodes, handlers=_full_handlers({"in": h_in}))
    # in, out, halt | in, out, halt
    insns = vl.disassemble(bytes.fromhex("060300060300"), spec)
    st = vl.interpret(insns, spec, input=b"XY")
    assert bytes(st.output) == b"X" and st.pc == 3 and st.steps == 3
    st.halted = False
    vl.interpret(insns, spec, state=st)                 # resume: pc 3, input and input_pos kept
    assert bytes(st.output) == b"XY" and st.pc == 6 and st.steps == 6
    # reset=True restarts at the first instruction; a new input rewinds input_pos
    st.halted = False
    vl.interpret(insns, spec, state=st, input=b"Z?", reset=True)
    assert bytes(st.output) == b"XYZ" and st.pc == 3


def test_interpret_rejects_missing_handler_and_bad_pc():
    # halt has no handler registered
    with pytest.raises(vl.VMRuntimeError, match="no handler for opcode 'push'"):
        vl.interpret(vl.disassemble(_PROG, _spec()), _spec())

    def h_jmp(st, ops):
        st.pc = ops[0]      # jump into the middle of an operand

    spec = _spec({"jmp": h_jmp})
    insns = vl.disassemble(b"\x04\x01\x00", spec)       # jmp 1 -> not an instruction boundary
    with pytest.raises(vl.VMRuntimeError, match="not at an instruction boundary"):
        vl.interpret(insns, spec, max_steps=10)


def test_count_limits_disassembly():
    insns = vl.disassemble(_PROG, _spec(), count=2)
    assert [i.name for i in insns] == ["push", "push"]


def test_spec_and_operand_validation():
    with pytest.raises(vl.VMError, match="no opcodes"):
        vl.VMSpec(opcodes={})
    with pytest.raises(vl.VMError, match="little|big"):
        vl.VMSpec(opcodes={0: vl.VMOp("x")}, endian="middle")
    with pytest.raises(vl.VMError, match="size must be"):
        vl.Operand("bad", 0)
    with pytest.raises(vl.VMError, match="no instructions"):
        vl.interpret([], _spec())


def test_lift_template_mismatch_raises():
    bad = vl.VMSpec(opcodes={0x01: vl.VMOp("push", (vl.Operand("imm", 2),), ir="push {0} {1}")})
    insns = vl.disassemble(b"\x01\x05\x00", bad)
    with pytest.raises(vl.VMLiftError, match="does not fit"):
        vl.lift(insns, bad)


def test_big_endian_operand_decode():
    spec = vl.VMSpec(opcodes={0x01: vl.VMOp("push", (vl.Operand("imm", 2, endian="big"),))},
                     endian="big")
    insns = vl.disassemble(b"\x01\x12\x34", spec)
    assert insns[0].operands == (0x1234,)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
