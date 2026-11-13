"""Capstone-backed inert encoding locks for multiarch.py (no code execution).

The semantic checker below consumes Capstone instructions, not the engine's
instruction words. Constants are Linux UAPI syscall numbers (asm-generic,
arch/arm/tools/syscall.tbl, arch/mips/kernel/syscalls/syscall_o32.tbl).
ROP expected words use the public loader register contracts and independent
int.to_bytes serialization, never a second call to the builder.
"""
import random

import capstone as C
import pytest
import multiarch as M
from contract import BuildError


SPECS = {
    'arm': (32, 'little', C.CS_ARCH_ARM, C.CS_MODE_ARM, 4, 1, 11, 32, 24),
    'armbe': (32, 'big', C.CS_ARCH_ARM, C.CS_MODE_ARM | C.CS_MODE_BIG_ENDIAN, 4, 1, 11, 32, 24),
    'aarch64': (64, 'little', C.CS_ARCH_ARM64, 0, 64, 93, 221, 32, 24),
    'mips': (32, 'big', C.CS_ARCH_MIPS, C.CS_MODE_MIPS32 | C.CS_MODE_BIG_ENDIAN, 4004, 4001, 4011, 40, 32),
    'mipsel': (32, 'little', C.CS_ARCH_MIPS, C.CS_MODE_MIPS32, 4004, 4001, 4011, 40, 32),
    'riscv64': (64, 'little', C.CS_ARCH_RISCV, C.CS_MODE_RISCV64, 64, 93, 221, 36, 28),
}


def decode_straight_line(code, spec):
    """Reference arithmetic model of these basic decoded setup instructions.

    This does not run machine code, import its contents, access target memory,
    perform a syscall or implement an emulator. It records setup register values
    observed by the Capstone-decoded svc/syscall/ecall instructions.
    """
    dis = C.Cs(spec[2], spec[3])
    dis.detail = True
    instructions = list(dis.disasm(code, 0))
    assert sum(i.size for i in instructions) == len(code)
    registers, calls = {}, []
    for insn in instructions:
        operands = insn.operands
        def value(op):
            if op.type == 2:
                return op.imm
            assert op.type == 1
            name = insn.reg_name(op.reg)
            if name == 'pc':
                return insn.address + 8  # ARM architectural PC in ARM state
            if name in ('zero', 'x0') and spec[2] in (C.CS_ARCH_MIPS, C.CS_ARCH_RISCV):
                return 0
            return registers[name]
        def assign(number, new):
            registers[insn.reg_name(operands[number].reg)] = new
        if insn.mnemonic in ('mov', 'mv'):
            assign(0, value(operands[1]))
        elif insn.mnemonic in ('add', 'addi', 'addiu'):
            assign(0, value(operands[1]) + value(operands[2]))
        elif insn.mnemonic == 'adr':
            assign(0, value(operands[1]))
        elif insn.mnemonic == 'auipc':
            assign(0, insn.address + (value(operands[1]) << 12))
        elif insn.mnemonic == 'bal':
            registers['ra'] = insn.address + 8
        elif insn.mnemonic in ('svc', 'syscall', 'ecall'):
            calls.append(dict(registers))
        else:
            assert insn.mnemonic in ('nop', 'udf', 'brk', 'break', 'ebreak')
    return instructions, calls


def syscall_registers(arch):
    if arch.startswith('arm'):
        return 'r7', ('r0', 'r1', 'r2')
    if arch == 'aarch64':
        return 'x8', ('x0', 'x1', 'x2')
    if arch.startswith('mips'):
        return 'v0', ('a0', 'a1', 'a2')
    return 'a7', ('a0', 'a1', 'a2')


@pytest.mark.parametrize('arch', SPECS)
def test_architecture_and_inventory_published_linux_values(arch):
    spec = SPECS[arch]
    value = M.architecture(arch)
    assert (value.bits, value.endian, value.write_syscall, value.exit_syscall, value.execve_syscall) == (spec[0], spec[1], *spec[4:7])
    assert M.available_builders()[arch] == ('marker_shellcode', 'execve_shellcode', 'call_rop', 'syscall_rop')
    assert set(M.available_builders()) == set(SPECS)


@pytest.mark.parametrize('arch', SPECS)
@pytest.mark.parametrize('marker', [b'CSCTF{opcode_lock}\n', b'X' * 255])
def test_marker_code_capstone_semantic_oracle(arch, marker):
    spec = SPECS[arch]
    result = M.build_marker_shellcode(arch, marker)
    instructions, calls = decode_straight_line(result.payload[:spec[7]], spec)
    number, args = syscall_registers(arch)
    assert len(calls) == 2
    assert calls[0][number] == spec[4]
    assert tuple(calls[0][r] for r in args) == (1, spec[7], len(marker))
    assert calls[1][number] == spec[5] and calls[1][args[0]] == 0
    assert result.payload[spec[7]:] == marker
    assert result.placements['marker'] == spec[7]
    syscall_addresses = [i.address for i in instructions if i.mnemonic in ('svc', 'syscall', 'ecall')]
    assert [result.placements['write_syscall'], result.placements['exit_syscall']] == syscall_addresses


@pytest.mark.parametrize('arch', SPECS)
def test_execve_code_capstone_semantic_oracle(arch):
    spec = SPECS[arch]
    path = b'/synthetic/not-executed'
    result = M.build_execve_shellcode(arch, path)
    _, calls = decode_straight_line(result.payload[:spec[8]], spec)
    number, args = syscall_registers(arch)
    assert len(calls) == 1 and calls[0][number] == spec[6]
    assert tuple(calls[0][r] for r in args) == (spec[8], 0, 0)
    assert result.payload[spec[8]:] == path + b'\0'
    assert result.placements['path'] == spec[8]


@pytest.mark.parametrize('arch', SPECS)
def test_call_rop_independent_endian_word_serializer(arch):
    bits, endian = SPECS[arch][:2]
    # Register counts and tail ordering come from the advertised loader contract.
    count = 4 if arch.startswith(('arm', 'mips')) else 8
    values = [0x11112222, 0x33, 0x44] + [0] * (count - 2)
    if arch.startswith('arm'):
        values += [0x55, 0x66667777, 0x88889999]
    else:
        values += [0x88889999, 0x66667777]
    result = M.build_call_rop(arch, loader_gadget=values[0], arguments=[0x33, 0x44],
                              function=0x88889999, continuation=0x66667777, scratch=0x55, stack_base=0x1000)
    assert result.payload == b''.join(v.to_bytes(bits // 8, endian) for v in values)
    assert result.base_address == 0x1000
    assert set(result.widths.values()) == {bits // 8}


@pytest.mark.parametrize('arch', SPECS)
def test_syscall_rop_independent_endian_word_serializer(arch):
    bits, endian = SPECS[arch][:2]
    count = 7 if arch.startswith('arm') else 4 if arch.startswith('mips') else 6
    values = [0x11112222, 0x33, 0x44] + [0] * (count - 2) + [SPECS[arch][4]]
    values += [0x66667777, 0x88889999] if arch.startswith('arm') else [0x88889999, 0x66667777]
    result = M.build_syscall_rop(arch, loader_gadget=values[0], arguments=[0x33, 0x44],
                                 syscall_gadget=0x88889999, syscall_number=SPECS[arch][4], continuation=0x66667777)
    assert result.payload == b''.join(v.to_bytes(bits // 8, endian) for v in values)


@pytest.mark.parametrize('entrypoint', [M.build_marker_shellcode, M.build_execve_shellcode])
def test_literal_builders_deterministic_fuzz(entrypoint):
    rng = random.Random(0xb1f047)
    inputs = [b'', b'\xff', bytes([255]) * 255, bytes([255]) * 256,
              b'MZ', b'\x7fELF', b'\x7fEL', b'\0asm', None, 123, [], '\ud800']
    inputs += [rng.randbytes(length) for length in (1, 2, 3, 7, 8, 31, 64, 254, 255, 256)]
    base = b'CSCTF{literal}'
    for at in range(len(base)):
        value = bytearray(base)
        value[at] ^= 1 << (at % 8)
        inputs.append(bytes(value))
    for arch in SPECS:
        for data in inputs:
            try:
                result = entrypoint(arch, data)
            except Exception as exc:
                assert type(exc) is BuildError, (arch, data, type(exc).__name__)
            else:
                assert isinstance(result.payload, bytes)


def test_architecture_names_fail_closed():
    rng = random.Random(37)
    for name in ['', 'ELF', 'MZ', None, 4, [], {}, b'arm', '\uffff', *[rng.randbytes(16).hex() for _ in range(20)]]:
        with pytest.raises(BuildError):
            M.architecture(name)


@pytest.mark.parametrize('builder', [M.build_call_rop, M.build_syscall_rop])
def test_rop_numeric_fuzz(builder):
    rng = random.Random(888)
    for arch in SPECS:
        for arg in [[], [0], [-1], [1 << 64], [None], [True], [0xff] * 20,
                    *[[rng.randrange(-(1 << 65), 1 << 65)] for _ in range(30)]]:
            kwargs = {'loader_gadget': 0x4000, 'arguments': arg}
            if builder is M.build_call_rop:
                kwargs['function'] = 0x5000
            else:
                kwargs.update(syscall_gadget=0x5000, syscall_number=1)
            try:
                result = builder(arch, **kwargs)
            except Exception as exc:
                assert type(exc) is BuildError, (arch, arg, type(exc).__name__)
            else:
                assert isinstance(result.payload, bytes)


@pytest.mark.parametrize('builder', [M.build_call_rop, M.build_syscall_rop])
def test_bug_rop_scalar_arguments_contract(builder):
    kwargs = {'loader_gadget': 0x1000, 'arguments': None}
    if builder is M.build_call_rop:
        kwargs['function'] = 0x2000
    else:
        kwargs.update(syscall_gadget=0x2000, syscall_number=1)
    with pytest.raises(BuildError):
        builder('arm', **kwargs)
