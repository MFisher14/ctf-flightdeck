"""Typed VM handler and program IR tests."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import vm_semantic_lifter as vm  # noqa: E402


def test_explicit_vm_stack_arithmetic_and_return_semantics():
    handler = vm.lift_vm_handler({
        "name": "op_add", "opcode": 1, "word_bits": 64,
        "disassembly": """
vpop r0
vpop r1
add r0, r1
vpush r0
vret
""",
        "register_roles": {"r0": "accumulator", "r1": "temporary"},
        "terminal": True,
    })
    assert [row.operation for row in handler.instructions] == [
        "stack_pop", "stack_pop", "binary_add", "stack_push", "vm_return"
    ]
    assert handler.stack_delta == -1
    assert handler.required_stack == 2
    assert handler.terminal
    assert handler.confidence == 100
    assert "stack_pop" in handler.render()


def test_native_role_mapping_lifts_stack_code_and_dispatch_operations():
    handler = vm.lift_vm_handler({
        "name": "op_xor_branch", "opcode": 2, "address": 0x1000,
        "register_roles": {"rdi": "vsp", "rsi": "vip", "rdx": "opcode", "rax": "accumulator"},
        "word_bits": 64, "stack_growth": "down",
        "disassembly": """
1000: mov rax, [rdi]
1004: add rdi, 8
1008: mov rbx, [rsi]
100c: add rsi, 1
1010: xor rax, rbx
1014: cmp rax, 0
1018: jne 0x2000
101c: jmp rdx
""",
    })
    operations = [row.operation for row in handler.instructions]
    assert operations == [
        "stack_load", "stack_adjust", "code_load", "advance_ip",
        "binary_xor", "compare_cmp", "branch_if", "dispatch",
    ]
    assert handler.stack_delta == -1 and handler.required_stack == 1
    assert handler.instructions[6].branch_targets == (0x2000,)
    assert handler.terminal
    assert {"vsp", "vip", "opcode"} <= set(handler.register_reads)


def test_memory_store_and_upward_stack_growth_are_typed():
    handler = vm.lift_vm_handler({
        "name": "store", "opcode": 3, "word_bits": 32, "stack_growth": "up",
        "register_roles": {"spv": "vsp"},
        "disassembly": "mov [spv], r0\nadd spv, 4\nret",
        "terminal": True,
    })
    assert handler.instructions[0].operation == "stack_store"
    assert handler.instructions[0].outputs[0].kind == "memory"
    assert handler.stack_delta == 1


def test_att_operand_order_symbols_and_stack_access_requirements():
    handler = vm.lift_vm_handler({
        "name": "att", "opcode": 6, "word_bits": 64,
        "register_roles": {"rdi": "vsp"},
        "disassembly": """
movq (%rdi), %rax
addq $1, %rax
vdup
vswap
jmp handler_tail
""",
    })
    assert handler.instructions[0].operation == "stack_load"
    assert handler.instructions[0].outputs[0].text == "%rax"
    assert handler.instructions[1].outputs[0].text == "%rax"
    assert handler.instructions[-1].inputs[0].kind == "symbol"
    assert "handler_tail" not in handler.register_reads
    assert handler.required_stack == 1  # vdup supplies vswap's second item
    swap_only = vm.lift_vm_handler({
        "name": "swap_only", "opcode": 8, "disassembly": "vswap\nvret", "terminal": True,
    })
    assert swap_only.required_stack == 2


def test_unparsed_instruction_like_lines_reduce_confidence_explicitly():
    handler = vm.lift_vm_handler({
        "name": "partial", "opcode": 7,
        "disassembly": "vpush r0\n??? malformed saved line\nvret",
        "terminal": True,
    })
    assert handler.confidence < 100
    assert any("unparsed disassembly line" in warning for warning in handler.warnings)
    assert "2/3" in handler.evidence[0]


def test_arm_riscv_three_operand_memory_and_branch_forms():
    handler = vm.lift_vm_handler({
        "name": "portable", "opcode": 5, "word_bits": 64,
        "register_roles": {"x10": "vsp", "x11": "vip"},
        "disassembly": """
0x1000: ld x5, [x10, #8]
0x1004: addi x10, x10, 8
0x1008: addi x11, x11, 2
0x100c: beq x5, x0, 0x2000
0x1010: jal 0x3000
""",
    })
    assert [row.operation for row in handler.instructions] == [
        "stack_load", "stack_adjust", "advance_ip", "branch_if", "call"
    ]
    assert handler.instructions[3].inputs[0].text == "x5"
    assert handler.instructions[3].branch_targets == (0x2000,)
    assert handler.instructions[4].branch_targets == (0x3000,)
    assert handler.stack_delta == -1


def test_program_dispatch_edges_and_order_are_deterministic():
    handlers = [
        {"name": "stop", "opcode": 2, "disassembly": "vret", "terminal": True},
        {"name": "start", "opcode": 1, "disassembly": "vfetch r0\nvbranch 0x20",
         "successors": ["stop"], "terminal": True},
    ]
    report = vm.lift_vm_program(handlers)
    assert [handler.name for handler in report.handlers] == ["start", "stop"]
    assert report.dispatch_table == ((1, "start"), (2, "stop"))
    assert report.edges == (("start", "stop"),)
    assert "dispatch 0x1 -> start" in report.render()
    assert report.to_dict()["handlers"][0]["opcode"] == 1


def test_unknown_instructions_are_preserved_with_lower_confidence():
    handler = vm.lift_vm_handler({
        "name": "mixed", "opcode": 4,
        "disassembly": "mystery r0, r1\nvpush r0\nvret", "terminal": True,
    })
    assert handler.instructions[0].operation == "native_unknown"
    assert handler.warnings and handler.confidence < 100


def test_invalid_graphs_roles_operands_and_duplicates_fail_closed():
    with pytest.raises(vm.VMLiftInputError, match="unique"):
        vm.lift_vm_program([
            {"name": "a", "opcode": 1, "disassembly": "vret"},
            {"name": "b", "opcode": 1, "disassembly": "vret"},
        ])
    with pytest.raises(vm.VMLiftInputError, match="unknown successor"):
        vm.lift_vm_program([
            {"name": "a", "opcode": 1, "disassembly": "vret", "successors": ["missing"]},
        ])
    with pytest.raises(vm.VMLiftInputError, match="role"):
        vm.lift_vm_handler({
            "name": "a", "opcode": 1, "disassembly": "vret",
            "register_roles": {"r0": "evil"},
        })
    with pytest.raises(vm.VMLiftInputError, match="brackets"):
        vm.lift_vm_handler({"name": "a", "opcode": 1, "disassembly": "mov r0, [vsp"})
    with pytest.raises(vm.VMLiftInputError, match="brackets"):
        vm.lift_vm_handler({"name": "a", "opcode": 1, "disassembly": "mov r0, [vsp)"})
    with pytest.raises(vm.VMLiftInputError, match="word_bits"):
        vm.lift_vm_handler({"name": "a", "opcode": 1, "word_bits": [], "disassembly": "vret"})
    with pytest.raises(vm.VMLiftInputError, match="128-bit"):
        vm.lift_vm_handler({"name": "a", "opcode": 1, "disassembly": f"jmp {1 << 200}"})


def test_caps_types_and_ast_safety(monkeypatch):
    with pytest.raises(TypeError, match="mapping"):
        vm.lift_vm_handler("vret")  # type: ignore[arg-type]
    monkeypatch.setattr(vm, "MAX_INSTRUCTIONS", 1)
    with pytest.raises(vm.VMLiftInputError, match="cap"):
        vm.lift_vm_handler({"name": "a", "opcode": 1, "disassembly": "vpush r0\nvret"})
    monkeypatch.setattr(vm, "MAX_SOURCE_LINES", 1)
    with pytest.raises(vm.VMLiftInputError, match="source-line cap"):
        vm.lift_vm_handler({"name": "a", "opcode": 1, "disassembly": "# one\nvret"})
    tree = ast.parse((REPO / "solvers" / "binary" / "vm_semantic_lifter.py").read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not imports & {"subprocess", "socket", "requests", "marshal", "pickle", "importlib"}
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}
