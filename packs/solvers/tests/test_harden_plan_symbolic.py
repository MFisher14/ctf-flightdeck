"""Static Z3 solver/lifter checks, using arithmetic, Capstone and ELF oracles.

https://microsoft.github.io/z3guide/docs/theories/Bitvectors/
https://www.capstone-engine.org/lang_python.html
https://gabi.xinuos.com/elf/02-eheader.html
Neither the fixture ELF nor its instructions are executed.
"""
import io
import random
import socket
import struct
import subprocess

import capstone
from capstone import x86
from elftools.elf.elffile import ELFFile
import pytest
import z3
import symbolic as engine


# movzx eax,byte ptr [rdi]; cmp eax,65; jne outside; mov eax,1; ret.
CHECK_A = bytes.fromhex("0fb60783f8417520b801000000c3")


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("symbolic analysis attempted binary execution or network")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def test_unique_integer_equations_and_repeatability():
    a, b = z3.Ints("fixture_a fixture_b")
    constraints = [a + b == 7, a - b == 1]
    oracle = z3.Solver()
    oracle.add(*constraints)
    assert oracle.check() == z3.sat
    assert (oracle.model()[a].as_long(), oracle.model()[b].as_long()) == (4, 3)
    oracle.add(z3.Or(a != 4, b != 3))
    assert oracle.check() == z3.unsat
    snapshots = []
    for _ in range(3):
        result = engine.solve([a, b], constraints)
        assert result.status == engine.UNIQUE
        assert result.plain() == {"fixture_a": 4, "fixture_b": 3}
        assert result.candidate_values() == []
        snapshots.append((result.status, result.models, result.checks))
    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert engine.solve_ints(2, lambda ns: [ns[0] + ns[1] == 7, ns[0] - ns[1] == 1]).plain() == {"n0": 4, "n1": 3}


def test_multiple_unsat_and_underconstrained_boundaries():
    x = z3.Int("fixture_x")
    result = engine.solve([x], [x >= 2, x <= 4])
    assert result.status == engine.MULTIPLE and result.plain() is None
    assert set(result.candidate_values()) == {2, 3, 4}
    result = engine.solve([x], [x == 1, x == 2])
    assert result.status == engine.UNSAT and result.plain() is None and result.candidate_values() == []
    result = engine.solve([x], [x >= 0, x <= 5], max_candidates=2)
    assert result.status == engine.UNDERCONSTRAINED and result.models == [] and result.plain() is None


def test_keygen_modular_arithmetic_and_mixed_bit_widths():
    def constraints(xs):
        return [xs[0] ^ 0xAA == 0xE1, xs[1] + 17 == 4, xs[2] == 0xFF]
    result = engine.keygen(3, constraints)
    assert result.plain() == bytes([0xE1 ^ 0xAA, (4 - 17) % 256, 255])
    assert engine.printable() == (32, 126)
    result = engine.solve_bitvecs([8, 16], lambda vs: [vs[0] + 1 == 0, vs[1] + 1 == 0])
    assert result.plain() == {"v0": 255, "v1": 65535}
    x = z3.BitVec("charset_byte", 8)
    result = engine.solve([x], engine.charset_constraints([x], (254, 255)))
    assert set(result.candidate_values()) == {254, 255}


def test_timeout_discards_unproven_models(monkeypatch):
    ticks = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(ticks))
    x = z3.Int("deadline_x")
    result = engine.solve([x], [x == 1], timeout_ms=1)
    assert result.status == engine.TIMEOUT and result.plain() is None and result.models == []


def _immediates_oracle(code, base):
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True
    return [(ins.address, ins.mnemonic, ins.op_str, operand.imm)
            for ins in disassembler.disasm(code, base)
            if ins.mnemonic in {"cmp", "mov", "xor", "add"}
            for operand in ins.operands if operand.type == x86.X86_OP_IMM]


def test_scan_immediates_against_real_capstone():
    code = bytes.fromhex("b87856341283f8073504030201c3")
    assert engine.scan_immediates(code, base=0x401000) == _immediates_oracle(code, 0x401000)
    assert [row[-1] for row in engine.scan_immediates(code, base=0x401000)] == [0x12345678, 7, 0x01020304]
    assert engine.scan_immediates(code, max_scan=5) == _immediates_oracle(code[:5], 0)
    assert engine.scan_immediates(code, arch="arm64") == []


def test_static_lift_known_check_and_fail_closed_unsupported_instruction():
    result = engine.lift_linear(CHECK_A, 1, base=0x401000)
    assert result.status == engine.UNIQUE and result.plain() == b"A"
    assert engine.lift_linear(CHECK_A, 1, charset=b"B").status == engine.UNSAT
    result = engine.lift_linear(bytes.fromhex("0f05c3"), 1)  # syscall; ret
    assert result.status == engine.PARTIAL and result.plain() is None
    result = engine.lift_linear(CHECK_A, 1, max_insns=1)
    assert result.status == engine.PARTIAL and result.plain() is None


def _elf_fixture():
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 0, 0x100, 0, 64, 0, 0, 64, 3, 2)
    names = b"\x00.text\x00.shstrtab\x00"
    prefix = (header + CHECK_A).ljust(0x80, b"\x00") + names
    text_header = struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x401000, 64, len(CHECK_A), 0, 0, 16, 0)
    names_header = struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, 0x80, len(names), 0, 0, 1, 0)
    return prefix.ljust(0x100, b"\x00") + b"\x00" * 64 + text_header + names_header


def test_elf_preparse_against_pyelftools_and_lift():
    raw = _elf_fixture()
    oracle = ELFFile(io.BytesIO(raw))
    assert oracle.header["e_machine"] == "EM_X86_64" and oracle.header["e_entry"] == 0x401000
    section = oracle.get_section_by_name(".text")
    assert section.data() == CHECK_A and section["sh_addr"] == 0x401000
    result = engine.cmp_constants(raw)
    assert result["arch"] == "amd64" and result["bits"] == 64
    assert result["sections"] == [(".text", _immediates_oracle(section.data(), section["sh_addr"]))]
    assert engine.lift_elf(raw, 1).plain() == b"A"
    assert engine.lift_elf(raw, 1, func=0x401000).plain() == b"A"
    assert engine.lift_elf(raw, 1, func="missing") is None


def test_lift_requires_all_fallthrough_bytes_decoded():
    # No ret: the final single 0f byte is a truncated x86 instruction.
    result = engine.lift_linear(CHECK_A[:-1] + b"\x0f", 1)
    assert result.status == engine.PARTIAL and result.plain() is None


def test_lift_rejects_wrong_architecture():
    try:
        result = engine.lift_linear(CHECK_A, 1, arch="arm64")
    except ValueError:
        return
    assert result.status == engine.PARTIAL and result.plain() is None


@pytest.mark.parametrize("charset", [[256], "界", (-1, 255)])
def test_charset_out_of_byte_range_is_not_reinterpreted(charset):
    with pytest.raises(ValueError):
        engine.keygen(1, lambda xs: [], charset=charset)


def test_declared_valueerror_validation_and_small_caps(monkeypatch):
    x = z3.Int("limit_x")
    for call in [lambda: engine.solve([], []), lambda: engine.keygen(0, lambda xs: []),
                 lambda: engine.solve_bitvecs([], lambda vs: []), lambda: engine.solve_ints(0, lambda vs: []),
                 lambda: engine.lift_linear(CHECK_A, 0)]:
        with pytest.raises(ValueError) as caught:
            call()
        assert type(caught.value) is ValueError
    monkeypatch.setattr(engine, "MAX_CONSTRAINTS", 2)
    with pytest.raises(ValueError):
        engine.solve([x], [x == 1] * 3)
    monkeypatch.setattr(engine, "MAX_BYTES", 2)
    with pytest.raises(ValueError):
        engine.keygen(3, lambda xs: [])


def test_seeded_static_binary_fuzz():
    rng = random.Random(0x5A7)
    corpus = [b"", b"\xff" * 64, bytes(rng.randrange(256) for _ in range(64))]
    corpus += [CHECK_A[:n] for n in range(len(CHECK_A))]
    corpus += [CHECK_A[:i] + bytes([CHECK_A[i] ^ 0x80]) + CHECK_A[i + 1:] for i in (0, 4, 8)]
    for raw in corpus:
        assert isinstance(engine.scan_immediates(raw, max_scan=32), list)
        result = engine.lift_linear(raw, 1, max_insns=8, timeout_ms=100, max_candidates=2)
        assert isinstance(result, engine.Solution)
    raw = _elf_fixture()
    for payload in [b"", b"\xff" * 64, raw[:4], raw[:63], raw[:128], raw[:-1]]:
        assert engine.cmp_constants(payload) is None
        assert engine.lift_elf(payload, 1) is None


@pytest.mark.parametrize("call", [
    lambda: engine.solve([z3.Int("bad")], 7),
    lambda: engine.solve([z3.Int("bad")], [], timeout_ms=None),
    lambda: engine.keygen(None, lambda xs: []),
    lambda: engine.solve_bitvecs(None, lambda xs: []),
    lambda: engine.solve_ints(None, lambda xs: []),
    lambda: engine.charset_constraints([], None),
    lambda: engine.cmp_constants(None),
    lambda: engine.lift_elf(None, 1),
    lambda: engine.lift_linear(None, 1),
    lambda: engine.lift_linear(CHECK_A, 1, base=float("inf")),
])
def test_malformed_argument_contract(call):
    try:
        call()
    except Exception as exc:
        assert type(exc) is ValueError


def test_constraint_depth_bound():
    x = z3.Int("deep_x")
    constraints = x == 1
    for _ in range(1500):
        constraints = [constraints]
    leaked = None
    try:
        engine.solve([x], constraints)
    except Exception as exc:
        if type(exc) is not ValueError:
            leaked = type(exc).__name__
    assert leaked is None, leaked


def test_cli_usage_is_clean(capsys):
    assert engine.main([]) == 2
