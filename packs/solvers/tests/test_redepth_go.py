"""Independent layout-vector tests for the static Go pclntab parser.

The fixture writer below follows the Go project's published source layouts;
it neither imports nor calls the engine's parser/serializer.  The relevant
upstream definitions are:

* https://go.dev/src/internal/abi/symtab.go (Go120PCLnTabMagic)
* https://go.dev/src/runtime/symtab.go (pcHeader)
* https://go.dev/src/runtime/runtime2.go (runtime._func)
* https://go.dev/src/cmd/link/internal/ld/pcln.go (functab construction)
"""
from __future__ import annotations

import ast
import json
import random
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import redepth_go as go  # noqa: E402


MAGIC = 0xFFFFFFF1
FUNC_SIZE = 44


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & -alignment


def _put_unsigned(blob: bytearray, offset: int, value: int, size: int, order: str) -> None:
    blob[offset:offset + size] = value.to_bytes(size, order, signed=False)


def _put_i32(blob: bytearray, offset: int, value: int, order: str) -> None:
    blob[offset:offset + 4] = value.to_bytes(4, order, signed=True)


def _published_layout_fixture(
    *, byte_order: str = "little", pointer_size: int = 8, text_start: int = 0x401000,
) -> tuple[bytes, dict[str, object]]:
    """Write a tiny Go 1.20+ pclntab without using engine code.

    The records deliberately include signed ArgsSizeUnknown, PC-data arrays,
    a funcdata sentinel, and three distinct function/name offsets.
    """

    names = ("main.main", "runtime.main", "main.helper")
    names_blob = b"".join(name.encode("utf-8") + b"\0" for name in names)
    name_offsets: list[int] = []
    cursor = 0
    for name in names:
        name_offsets.append(cursor)
        cursor += len(name.encode("utf-8")) + 1

    header_size = 8 + 8 * pointer_size
    funcname_offset = header_size
    cu_offset = _align(funcname_offset + len(names_blob), 4)
    cutab = b"\0" * 8
    filetab_offset = cu_offset + len(cutab)
    filetab = b"main.go\0runtime/proc.go\0"
    pctab_offset = filetab_offset + len(filetab)
    pctab = bytes(range(16))
    pcln_offset = _align(pctab_offset + len(pctab), 4)

    entries = (0x00, 0x30, 0x60)
    terminal_entry = 0x90
    nfunc = len(entries)
    functab_size = (2 * nfunc + 1) * 4
    record_offsets: list[int] = []
    record_cursor = _align(functab_size, pointer_size)
    for _ in entries:
        record_offsets.append(record_cursor)
        # Fixed _func, two pcdata uint32s, one funcdata uint32.
        record_cursor = _align(record_cursor + FUNC_SIZE + 12, pointer_size)

    blob = bytearray(pcln_offset + record_cursor)
    blob[0:4] = MAGIC.to_bytes(4, byte_order)
    blob[4:8] = b"\0\0" + bytes((1, pointer_size))
    words = (
        nfunc,
        2,
        text_start,
        funcname_offset,
        cu_offset,
        filetab_offset,
        pctab_offset,
        pcln_offset,
    )
    for index, word in enumerate(words):
        _put_unsigned(blob, 8 + index * pointer_size, word, pointer_size, byte_order)

    blob[funcname_offset:funcname_offset + len(names_blob)] = names_blob
    blob[cu_offset:cu_offset + len(cutab)] = cutab
    blob[filetab_offset:filetab_offset + len(filetab)] = filetab
    blob[pctab_offset:pctab_offset + len(pctab)] = pctab

    for index, (entry, record_offset) in enumerate(zip(entries, record_offsets)):
        table_position = pcln_offset + index * 8
        _put_unsigned(blob, table_position, entry, 4, byte_order)
        _put_unsigned(blob, table_position + 4, record_offset, 4, byte_order)
    _put_unsigned(blob, pcln_offset + nfunc * 8, terminal_entry, 4, byte_order)

    args_sizes = (16, -(1 << 31), 8)  # runtime.ArgsSizeUnknown in the middle.
    start_lines = (3, 201, 17)
    func_ids = (0, 17, 0)  # FuncID_runtime_main is 17 in the published ABI.
    for index, record_offset in enumerate(record_offsets):
        record = pcln_offset + record_offset
        _put_unsigned(blob, record, entries[index], 4, byte_order)
        _put_i32(blob, record + 4, name_offsets[index], byte_order)
        _put_i32(blob, record + 8, args_sizes[index], byte_order)
        _put_unsigned(blob, record + 12, 0x10 if index == 1 else 0, 4, byte_order)
        _put_unsigned(blob, record + 16, 4, 4, byte_order)
        _put_unsigned(blob, record + 20, 8, 4, byte_order)
        _put_unsigned(blob, record + 24, 12, 4, byte_order)
        _put_unsigned(blob, record + 28, 2, 4, byte_order)
        # cuOffset is an index into []uint32 cutab despite its byte-ish name.
        _put_unsigned(blob, record + 32, index & 1, 4, byte_order)
        _put_i32(blob, record + 36, start_lines[index], byte_order)
        blob[record + 40:record + 44] = bytes((func_ids[index], index & 1, 0, 1))
        _put_unsigned(blob, record + 44, 0, 4, byte_order)
        _put_unsigned(blob, record + 48, 4, 4, byte_order)
        _put_unsigned(blob, record + 52, 0xFFFFFFFF, 4, byte_order)

    metadata: dict[str, object] = {
        "names": names,
        "name_offsets": tuple(name_offsets),
        "entries": entries,
        "terminal_entry": terminal_entry,
        "record_offsets": tuple(record_offsets),
        "funcname_offset": funcname_offset,
        "cu_offset": cu_offset,
        "pctab_offset": pctab_offset,
        "pcln_offset": pcln_offset,
        "end": pcln_offset + record_cursor,
    }
    return bytes(blob), metadata


def _wrap(table: bytes, kind: str) -> tuple[bytes, int]:
    if kind == "ELF":
        prefix = bytearray(0x100)
        prefix[:16] = b"\x7fELF" + bytes((2, 1, 1)) + b"\0" * 9
    elif kind == "Mach-O":
        prefix = bytearray(0x100)
        prefix[:4] = b"\xcf\xfa\xed\xfe"  # little-endian 64-bit Mach-O.
    elif kind == "PE":
        prefix = bytearray(0x200)
        prefix[:2] = b"MZ"
        prefix[0x3C:0x40] = (0x80).to_bytes(4, "little")
        prefix[0x80:0x84] = b"PE\0\0"
    else:
        raise AssertionError(kind)
    return bytes(prefix) + table, len(prefix)


def test_published_little_endian_64bit_layout_recovers_exact_structure():
    data, expected = _published_layout_fixture()
    report = go.parse_pclntab(data)

    assert report.container == "raw-pclntab"
    assert report.table_offset == 0
    assert report.header.magic_hex == "0xfffffff1"
    assert report.header.version == "Go 1.20+"
    assert report.header.byte_order == "little"
    assert report.header.pointer_size == 8
    assert report.header.header_size == 72
    assert report.header.function_count == 3
    assert report.header.file_count == 2
    assert report.header.text_start == 0x401000
    assert report.header.text_start_available is True
    assert report.header.funcname_offset == expected["funcname_offset"]
    assert report.header.pcln_offset == expected["pcln_offset"]
    assert report.validated_span_end_offset == expected["end"] == len(data)

    functions = report.functions
    assert tuple(function.name for function in functions) == expected["names"]
    assert tuple(function.entry_offset for function in functions) == expected["entries"]
    assert tuple(function.end_offset for function in functions) == (0x30, 0x60, 0x90)
    assert tuple(function.nominal_entry_pc for function in functions) == (
        0x401000, 0x401030, 0x401060,
    )
    assert tuple(function.func_offset for function in functions) == expected["record_offsets"]
    assert tuple(function.name_offset for function in functions) == expected["name_offsets"]
    assert functions[0].functab_entry_offset == expected["pcln_offset"]
    assert functions[1].func_record_offset == expected["pcln_offset"] + expected["record_offsets"][1]  # type: ignore[operator,index]
    assert functions[2].name_record_offset == expected["funcname_offset"] + expected["name_offsets"][2]  # type: ignore[operator,index]
    assert tuple(function.args_size for function in functions) == (16, -(1 << 31), 8)
    assert tuple(function.start_line for function in functions) == (3, 201, 17)
    assert functions[1].func_id == 17
    assert functions[1].flags == 1
    assert tuple(function.cu_offset for function in functions) == (0, 1, 0)
    assert all(function.pcdata_offsets == (0, 4) for function in functions)
    assert all(function.funcdata_offsets == (0xFFFFFFFF,) for function in functions)
    assert "file/line" in report.limitations[0]


def test_published_big_endian_32bit_layout_and_json_are_supported():
    data, expected = _published_layout_fixture(byte_order="big", pointer_size=4)
    report = go.analyze_go(data)
    assert report.header.byte_order == "big"
    assert report.header.pointer_size == 4
    assert report.header.header_size == 40
    assert report.header.pcln_offset == expected["pcln_offset"]
    assert [function.name for function in report.functions] == list(expected["names"])
    assert report.functions[-1].nominal_end_pc == 0x401090

    encoded = json.loads(json.dumps(report.to_dict()))
    assert encoded["header"]["byte_order"] == "big"
    assert encoded["functions"][1]["args_size"] == -(1 << 31)
    assert encoded["functions"][0]["pcdata_offsets"] == [0, 4]


def test_zero_or_unrelocated_entry_base_is_reported_without_inventing_pcs():
    data, _ = _published_layout_fixture(text_start=0)
    report = go.parse_pclntab(data)
    assert report.header.text_start == 0
    assert report.header.text_start_available is False
    assert all(function.nominal_entry_pc is None for function in report.functions)
    assert all(function.nominal_end_pc is None for function in report.functions)
    assert "zero/unavailable" in report.limitations[1]


@pytest.mark.parametrize("kind", ("ELF", "Mach-O", "PE"))
def test_structural_scan_recovers_table_and_absolute_offsets_in_containers(kind):
    table, expected = _published_layout_fixture()
    wrapped, base = _wrap(table, kind)
    report = go.analyze_go(wrapped)

    assert report.container == kind
    assert report.table_offset == base
    assert report.funcname_file_offset == base + expected["funcname_offset"]  # type: ignore[operator]
    assert report.functab_file_offset == base + expected["pcln_offset"]  # type: ignore[operator]
    assert report.functions[1].functab_entry_file_offset == base + expected["pcln_offset"] + 8  # type: ignore[operator]
    assert report.functions[1].func_record_file_offset == (
        base + expected["pcln_offset"] + expected["record_offsets"][1]  # type: ignore[operator,index]
    )
    assert wrapped[report.functions[0].name_record_file_offset:].startswith(b"main.main\0")

    with pytest.raises(go.RedepthGoError):
        go.parse_pclntab(wrapped)


def test_layout_corruptions_fail_closed_with_declared_error_only():
    valid, meta = _published_layout_fixture()
    pcln = int(meta["pcln_offset"])
    records = meta["record_offsets"]
    first_record = pcln + records[0]  # type: ignore[index,operator]

    cases: list[bytes] = []
    for index, value in ((4, 1), (6, 3), (7, 16)):
        mutated = bytearray(valid)
        mutated[index] = value
        cases.append(bytes(mutated))

    old_magic = bytearray(valid)
    old_magic[:4] = (0xFFFFFFF0).to_bytes(4, "little")
    cases.append(bytes(old_magic))

    unsorted = bytearray(valid)
    _put_unsigned(unsorted, pcln + 8, 0x70, 4, "little")
    cases.append(bytes(unsorted))

    mismatch = bytearray(valid)
    _put_unsigned(mismatch, first_record, 1, 4, "little")
    cases.append(bytes(mismatch))

    middle_name = bytearray(valid)
    _put_i32(middle_name, first_record + 4, 1, "little")
    cases.append(bytes(middle_name))

    bad_utf8 = bytearray(valid)
    bad_utf8[int(meta["funcname_offset"])] = 0xFF
    cases.append(bytes(bad_utf8))

    bad_padding = bytearray(valid)
    bad_padding[first_record + 42] = 1
    cases.append(bytes(bad_padding))

    huge_pcdata = bytearray(valid)
    _put_unsigned(huge_pcdata, first_record + 28, go.MAX_AUX_WORDS + 1, 4, "little")
    cases.append(bytes(huge_pcdata))

    bad_pcdata = bytearray(valid)
    _put_unsigned(bad_pcdata, first_record + 48, 16, 4, "little")
    cases.append(bytes(bad_pcdata))

    bad_cu_index = bytearray(valid)
    # cutab has exactly two uint32 words, so index 2 is one-past-end.
    _put_unsigned(bad_cu_index, first_record + 32, 2, 4, "little")
    cases.append(bytes(bad_cu_index))

    cases.extend((b"", valid[:7], valid[:-1]))
    for malformed in cases:
        with pytest.raises(go.RedepthGoError):
            go.parse_pclntab(malformed)
        with pytest.raises(go.RedepthGoError):
            go.analyze_go(malformed)

    for not_bytes in (bytearray(valid), memoryview(valid), "not bytes", None):
        with pytest.raises(go.RedepthGoError):
            go.parse_pclntab(not_bytes)  # type: ignore[arg-type]


def test_deterministic_mutation_contract_never_leaks_stdlib_exceptions():
    valid, _ = _published_layout_fixture()
    rng = random.Random(0x1202026)
    for _ in range(180):
        mutated = bytearray(valid)
        for _ in range(1 + rng.randrange(4)):
            position = rng.randrange(len(mutated))
            mutated[position] ^= 1 << rng.randrange(8)
        for function in (go.parse_pclntab, go.analyze_go):
            try:
                function(bytes(mutated))
            except Exception as exc:  # Contract assertion: no stdlib exception leaks.
                assert isinstance(exc, go.RedepthGoError)


def test_multiple_valid_tables_are_ambiguous_not_silently_selected():
    table, _ = _published_layout_fixture()
    joined = b"prefix" + table + b"padding" + table
    with pytest.raises(go.RedepthGoError, match="multiple valid"):
        go.analyze_go(joined)


def test_scanner_ignores_raw_magic_noise_without_header_invariants():
    table, _ = _published_layout_fixture()
    noise = (b"\xf1\xff\xff\xffNOIS" + b"\xff\xff\xff\xf1JUNK") * 100
    report = go.analyze_go(noise + table)
    assert report.table_offset == len(noise)
    assert report.functions[0].name == "main.main"


def test_guarded_cli_outputs_json_and_never_leaks_argparse_systemexit(tmp_path, capsys):
    table, _ = _published_layout_fixture()
    path = tmp_path / "tiny.gopclntab"
    path.write_bytes(table)

    assert go.main([str(path), "--raw"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["functions"][0]["name"] == "main.main"
    assert output["header"]["version"] == "Go 1.20+"

    assert go.main(["--not-an-option"]) == 2
    capsys.readouterr()
    assert go.main([str(tmp_path / "missing")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_engine_is_static_and_has_exact_guard_clause():
    path = REPO / "solvers" / "binary" / "redepth_go.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    assert not imported & {"ctypes", "marshal", "socket", "subprocess"}
    assert "exec(" not in source and "eval(" not in source
    assert "except SystemExit as exc:\n            return exc.code if isinstance(exc.code, int) else 2" in source

