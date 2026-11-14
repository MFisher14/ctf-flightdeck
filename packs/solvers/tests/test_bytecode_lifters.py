"""Deterministic structural tests for all r5d bytecode lifters."""
from __future__ import annotations

import ast
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import bytecode_lifters as lift  # noqa: E402


def test_pyc_headers_are_structural_and_payload_stays_opaque():
    magic = b"\xa7\x0d\r\n"
    timestamp = magic + struct.pack("<III", 0, 123, 456) + b"opaque payload"
    header = lift.inspect_pyc_header(timestamp)
    assert header.magic_hex == magic.hex()
    assert header.timestamp == 123 and header.source_size == 456
    assert header.hash_based is False

    hashed = magic + struct.pack("<I", 3) + bytes.fromhex("0011223344556677")
    hash_header = lift.inspect_pyc_header(hashed)
    assert hash_header.hash_based and hash_header.checked_hash
    assert hash_header.source_hash_hex == "0011223344556677"
    with pytest.raises(lift.LiftError, match="reserved"):
        lift.inspect_pyc_header(magic + struct.pack("<I", 4) + b"\0" * 8)
    with pytest.raises(lift.LiftError, match="truncated"):
        lift.inspect_pyc_header(magic)
    with pytest.raises(lift.LiftError, match="invalid"):
        lift.inspect_pyc_header(b"\0\0\r\n" + b"\0" * 12)


def test_python_wordcode_lifts_names_constants_extended_args_and_branches():
    code = bytes((
        100, 0,       # LOAD_CONST 0
        125, 0,       # STORE_FAST 0
        110, 1,       # JUMP_FORWARD one code unit
        124, 0,       # LOAD_FAST 0
        83, 0,        # RETURN_VALUE
    ))
    result = lift.lift_python_wordcode(code, constants=("42",), locals_=("answer",))
    assert [row.mnemonic for row in result.instructions] == [
        "LOAD_CONST", "STORE_FAST", "JUMP_FORWARD", "LOAD_FAST", "RETURN_VALUE"
    ]
    assert result.instructions[0].annotation == "42"
    assert result.instructions[1].annotation == "answer"
    assert result.instructions[2].branch_targets == (8,)
    assert "000000: LOAD_CONST 0 ; 42" in result.render()

    extended = lift.lift_python_wordcode(bytes((144, 1, 100, 2)), constants=tuple(str(i) for i in range(259)))
    assert extended.instructions[1].operands == ("258",)
    assert extended.instructions[1].annotation == "258"
    with pytest.raises(lift.LiftError, match="truncated"):
        lift.lift_python_wordcode(b"\x64")
    with pytest.raises(ValueError, match="explicit"):
        lift.lift_python_wordcode(b"", version="3.10")
    with pytest.raises(lift.LiftError, match="EXTENDED_ARG"):
        lift.lift_python_wordcode(bytes((144, 0)))


def _lua51_word(opcode: int, a: int = 0, b: int = 0, c: int = 0) -> bytes:
    word = opcode | (a << 6) | (c << 14) | (b << 23)
    return struct.pack("<I", word)


def test_lua_header_and_lua51_instruction_fields():
    header = b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00"
    parsed = lift.inspect_lua_header(header)
    assert parsed.version == "5.1" and parsed.endian == "little"
    loadk_word = 1 | (1 << 6) | (2 << 14)
    code = struct.pack("<I", loadk_word) + _lua51_word(30, a=1, b=2)
    result = lift.lift_lua51_instructions(code)
    assert result.instructions[0].mnemonic == "LOADK"
    assert result.instructions[0].operands == ("R1", "2")
    assert result.instructions[1].mnemonic == "RETURN"
    with pytest.raises(lift.LiftError, match="aligned"):
        lift.lift_lua51_instructions(b"\0")
    with pytest.raises(lift.LiftError, match="check-data"):
        lift.inspect_lua_header(b"\x1bLua\x53\0" + b"badbad" + b"\x04" * 5)
    lua53 = (
        b"\x1bLua\x53\0\x19\x93\r\n\x1a\n" + bytes((4, 8, 4, 8, 8))
        + (0x5678).to_bytes(8, "little", signed=True) + struct.pack("<d", 370.5)
    )
    assert lift.inspect_lua_header(lua53).endian == "little"
    with pytest.raises(lift.LiftError, match="truncated"):
        lift.inspect_lua_header(lua53[:-1])


def test_dotnet_tiny_method_and_relative_branch_targets():
    code = bytes((0x1F, 5, 0x2B, 1, 0x16, 0x2A))
    body = bytes(((len(code) << 2) | 2,)) + code
    result = lift.lift_dotnet_method(body)
    assert [row.mnemonic for row in result.instructions] == ["ldc.i4.s", "br.s", "ldc.i4.0", "ret"]
    assert result.instructions[1].branch_targets == (5,)
    assert result.instructions[0].operands == ("5",)
    with pytest.raises(lift.LiftError, match="truncated"):
        lift.lift_dotnet_method(bytes(((10 << 2) | 2, 0x2A)))
    with pytest.raises(lift.LiftError, match="switch"):
        lift.lift_dotnet_il(b"\x45\x01\x10\x00\x00")
    stopped = lift.lift_dotnet_il(b"\x24\x20\x01\x00\x00\x00")
    assert len(stopped.instructions) == 1
    assert "lifting stopped" in stopped.warnings[0]


def test_jvm_operands_branches_and_reserved_bytes():
    code = bytes((0x04, 0x99, 0x00, 0x05, 0x10, 0x07, 0xAC))
    result = lift.lift_jvm_code(code)
    assert [row.mnemonic for row in result.instructions] == ["iconst_1", "ifeq", "bipush", "ireturn"]
    assert result.instructions[1].branch_targets == (6,)
    assert result.instructions[2].operands == ("7",)

    with pytest.raises(lift.LiftError, match="reserved"):
        lift.lift_jvm_code(b"\xb9\x00\x01\x01\x01")
    with pytest.raises(lift.LiftError, match="operand"):
        lift.lift_jvm_code(b"\xaa")
    wide = lift.lift_jvm_code(b"\xc4\x16\x01\x02\xb1")
    assert wide.instructions[0].operands == ("lload", "258")


def test_wasm_function_and_module_code_section_are_bounded():
    function = b"\x41\x2a\x0b"  # i32.const 42; end
    lifted = lift.lift_wasm_function(function)
    assert [row.mnemonic for row in lifted.instructions] == ["i32.const", "end"]
    assert lifted.instructions[0].operands == ("42",)
    assert lifted.warnings == ()

    # code payload: one function, body size four, zero local groups, then code.
    module = (
        b"\0asm\x01\0\0\0" + b"\x03\x02\x01\x00"
        + b"\x0a\x06\x01\x04\x00" + function
    )
    report = lift.lift_wasm_module(module)
    assert report.sections == ((3, 2), (10, 6))
    assert len(report.functions) == 1
    assert report.functions[0].instructions[0].mnemonic == "i32.const"
    assert report.to_dict()["version"] == 1
    with pytest.raises(lift.LiftError, match="section"):
        lift.lift_wasm_module(module[:-1])
    with pytest.raises(lift.LiftError, match="header"):
        lift.lift_wasm_module(b"\0asm\0\0\0\0")
    with pytest.raises(lift.LiftError, match="unsupported WASM opcode"):
        lift.lift_wasm_function(b"\xfd\x00\x0b")
    mismatch = b"\0asm\x01\0\0\0" + b"\x03\x02\x01\x00" + b"\x0a\x01\x00"
    with pytest.raises(lift.LiftError, match="mismatch"):
        lift.lift_wasm_module(mismatch)
    with_data_count = (
        b"\0asm\x01\0\0\0" + b"\x03\x02\x01\x00" + b"\x0c\x01\x00"
        + b"\x0a\x06\x01\x04\x00" + function
    )
    assert [row[0] for row in lift.lift_wasm_module(with_data_count).sections] == [3, 12, 10]


def test_type_and_size_caps_are_enforced(monkeypatch):
    with pytest.raises(TypeError, match="bytes"):
        lift.lift_jvm_code(bytearray(b"\xb1"))  # type: ignore[arg-type]
    monkeypatch.setattr(lift, "MAX_BYTECODE", 3)
    with pytest.raises(lift.LiftError, match="cap"):
        lift.lift_dotnet_il(b"\x00" * 4)


def test_lifter_ast_has_no_runtime_loader_or_execution_primitives():
    source = (REPO / "solvers" / "binary" / "bytecode_lifters.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported & {
        "marshal", "pickle", "dis", "types", "importlib", "subprocess", "socket", "requests"
    }
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"exec", "eval", "compile", "open", "__import__"}
