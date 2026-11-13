"""Oracle-backed tests for the static Python 3.12/3.13 pyc inspector."""
from __future__ import annotations

import ast
import dis
import json
import py_compile
import random
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import redepth_pyc as pyc  # noqa: E402


SOURCE = """\
VALUE = 7

def check(candidate):
    total = 0
    try:
        for index in range(3):
            total += candidate[index] ^ index
        return total == VALUE and candidate != "CSCTF{trusted_sample}"
    except (TypeError, IndexError):
        return False
"""


def _compile_fixture(tmp_path: Path, *, hashed: bool = False) -> tuple[bytes, object]:
    source_path = tmp_path / "trusted_sample.py"
    pyc_path = tmp_path / "trusted_sample.pyc"
    source_path.write_text(SOURCE, encoding="utf-8")
    mode = py_compile.PycInvalidationMode.CHECKED_HASH if hashed else py_compile.PycInvalidationMode.TIMESTAMP
    py_compile.compile(str(source_path), cfile=str(pyc_path), doraise=True, invalidation_mode=mode)
    return pyc_path.read_bytes(), compile(SOURCE, str(source_path), "exec")


def _oracle_rows(code: object) -> list[tuple[int, str, int | None]]:
    return [(row.offset, row.opname, row.arg) for row in dis.get_instructions(code, show_caches=True)]


def _reported_rows(code: pyc.CodeInfo) -> list[tuple[int, str, int | None]]:
    return [
        (row.physical_offset, row.opname, 0 if row.is_cache else row.argument)
        for row in code.instructions
    ]


def test_compiled_python312_structure_caches_jumps_and_exceptions_match_stdlib(tmp_path):
    data, oracle_root = _compile_fixture(tmp_path)
    report = pyc.analyze_pyc(data)

    assert report.header.version == "3.12"
    assert report.header.magic_hex == "cb0d0d0a"
    assert report.header.hash_based is False
    assert report.marshal_references > 0  # exercises FLAG_REF and TYPE_REF.
    assert report.root.name == "<module>"
    assert report.root.names == oracle_root.co_names
    assert report.root.code_size == len(oracle_root.co_code)
    assert _reported_rows(report.root) == _oracle_rows(oracle_root)

    oracle_child = next(item for item in oracle_root.co_consts if isinstance(item, type(oracle_root)))
    child = report.root.children[0]
    assert child.name == oracle_child.co_name == "check"
    assert child.qualname == oracle_child.co_qualname
    assert child.names == oracle_child.co_names
    assert child.localsplus_names == oracle_child.co_varnames + oracle_child.co_cellvars + oracle_child.co_freevars
    assert child.code_size == len(oracle_child.co_code)
    assert len(child.instructions) == len(oracle_child.co_code) // 2
    assert _reported_rows(child) == _oracle_rows(oracle_child)
    assert any(row.is_cache and row.cache_owner_offset is not None for row in child.instructions)
    assert any("CSCTF{trusted_sample}" in value for value in child.constants)

    ours_by_offset = {row.physical_offset: row for row in child.instructions if not row.is_cache}
    for row in dis.get_instructions(oracle_child):
        if row.opcode in dis.hasjrel:
            assert ours_by_offset[row.offset].jump_target == row.argval

    expected_exceptions = [
        (row.start, row.end, row.target, row.depth, row.lasti)
        for row in dis.Bytecode(oracle_child).exception_entries
    ]
    assert [
        (row.start, row.end, row.target, row.depth, row.lasti)
        for row in child.exception_entries
    ] == expected_exceptions


def test_python312_checked_hash_header_matches_py_compile_oracle(tmp_path):
    data, _ = _compile_fixture(tmp_path, hashed=True)
    report = pyc.analyze_pyc(data)
    assert report.header.flags == 3
    assert report.header.hash_based and report.header.checked_hash
    assert report.header.source_hash_hex == data[8:16].hex()
    assert report.header.timestamp is None and report.header.source_size is None


# Independent, deliberately tiny marshal-v4 encoder used only by this test.
# Field order comes from CPython 3.13 Python/marshal.c; opcodes come from the
# generated CPython 3.13 Lib/_opcode_metadata.py.  It does not call the engine.
def _i32(value: int) -> bytes:
    return struct.pack("<i", value)


def _m_bytes(value: bytes) -> bytes:
    return b"s" + _i32(len(value)) + value


def _m_ascii(value: str) -> bytes:
    raw = value.encode("ascii")
    assert len(raw) < 256
    return b"z" + bytes((len(raw),)) + raw


def _m_tuple(values: list[bytes]) -> bytes:
    assert len(values) < 256
    return b")" + bytes((len(values),)) + b"".join(values)


def _python313_vector() -> bytes:
    # RESUME; LOAD_GLOBAL with four caches; POP_JUMP_IF_FALSE with one cache;
    # and two RETURN_CONST instructions.  The conditional target is offset 18.
    wordcode = bytes((
        149, 0,
        91, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        97, 1, 0, 0,
        103, 0,
        103, 0,
    ))
    code = (
        b"c"
        + _i32(0) + _i32(0) + _i32(0) + _i32(1) + _i32(0)
        + _m_bytes(wordcode)
        + _m_tuple([b"N"])
        + _m_tuple([_m_ascii("flag")])
        + _m_tuple([])
        + _m_bytes(b"")
        + _m_ascii("fixture.py")
        + _m_ascii("<module>")
        + _m_ascii("<module>")
        + _i32(1)
        + _m_bytes(b"")
        + _m_bytes(b"")
    )
    # PEP 552 timestamp header, with zeroed timestamp/source size.
    return bytes.fromhex("f30d0d0a") + _i32(0) + _i32(0) + _i32(0) + code


def test_authoritative_python313_schema_and_opcode_vector():
    report = pyc.analyze_pyc(_python313_vector())
    assert report.header.version == "3.13"
    assert report.root.filename == "fixture.py"
    assert report.root.constants == ("None",)
    main = [row for row in report.root.instructions if not row.is_cache]
    assert [(row.opname, row.argument, row.annotation) for row in main] == [
        ("RESUME", 0, ""),
        ("LOAD_GLOBAL", 0, "flag"),
        ("POP_JUMP_IF_FALSE", 1, ""),
        ("RETURN_CONST", 0, "None"),
        ("RETURN_CONST", 0, "None"),
    ]
    assert len([row for row in report.root.instructions if row.is_cache]) == 5
    assert main[2].jump_target == 18


def test_all_malformed_inputs_raise_only_declared_error(tmp_path):
    valid, _ = _compile_fixture(tmp_path)
    cases: list[object] = [
        bytearray(valid),
        b"",
        valid[:15],
        b"\0\0\0\0" + valid[4:],
        valid[:16] + b"?",
        bytes.fromhex("cb0d0d0a02000000") + b"\0" * 8 + b"N",
    ]
    for case in cases:
        with pytest.raises(pyc.RedepthPycError):
            pyc.analyze_pyc(case)  # type: ignore[arg-type]

    for length in (16, 17, 31, len(valid) - 1):
        with pytest.raises(pyc.RedepthPycError):
            pyc.analyze_pyc(valid[:length])

    rng = random.Random(0x312313)
    for _ in range(120):
        mutated = bytearray(valid)
        for _ in range(1 + rng.randrange(3)):
            index = rng.randrange(len(mutated))
            mutated[index] ^= 1 << rng.randrange(8)
        try:
            pyc.analyze_pyc(bytes(mutated))
        except Exception as exc:  # Contract assertion: no stdlib exception leaks.
            assert isinstance(exc, pyc.RedepthPycError)


def test_orphan_cache_and_bad_reference_fail_closed():
    vector = bytearray(_python313_vector())
    # Locate the unique RESUME/RETURN_CONST code blob and turn RESUME into CACHE.
    position = vector.index(bytes((149, 0, 91, 0)))
    vector[position] = 0
    with pytest.raises(pyc.RedepthPycError, match="orphan"):
        pyc.analyze_pyc(bytes(vector))

    # A marshal root back-reference with no reserved object.
    bad_ref = bytes.fromhex("cb0d0d0a") + b"\0" * 12 + b"r" + _i32(0)
    with pytest.raises(pyc.RedepthPycError, match="back-reference"):
        pyc.analyze_pyc(bad_ref)


def test_guarded_cli_json_and_no_systemexit(tmp_path, capsys):
    data, _ = _compile_fixture(tmp_path)
    path = tmp_path / "sample.pyc"
    path.write_bytes(data)
    assert pyc.main([str(path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["header"]["version"] == "3.12"
    assert payload["root"]["children"][0]["name"] == "check"

    assert pyc.main([]) == 2
    assert "required" in capsys.readouterr().err
    assert pyc.main(["--help"]) == 0
    assert "Python 3.12 or 3.13" in capsys.readouterr().out


def test_engine_has_no_runtime_loader_execution_or_network_primitives():
    path = REPO / "solvers" / "binary" / "redepth_pyc.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not imports & {
        "marshal", "dis", "types", "importlib", "subprocess", "socket", "requests", "urllib"
    }
    assert not calls & {"exec", "eval", "compile", "__import__"}
