"""Independent vectors and fail-closed fuzz for four static depth engines.

The trusted artifacts are compiled by CPython/Swift/Go or written directly
from Go's published ``pcHeader`` and ``runtime._func`` layouts.  No expected
value is obtained from an engine serializer or a previous engine run.
"""
from __future__ import annotations

import dis
import hashlib
import marshal
import os
import py_compile
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import redepth_go as go
import redepth_js_bundle as js
import redepth_pyc as pyc
import redepth_swift as swift


PY_SOURCE = """\
SENTINEL = "CSCTF{pyc_vector_lock}"

def grid_sum(values):
    total = 0
    for value in values:
        total += value
    return total, SENTINEL
"""


@pytest.fixture(scope="module")
def compiled_pyc(tmp_path_factory: pytest.TempPathFactory) -> tuple[bytes, object]:
    if sys.version_info[:2] not in {(3, 12), (3, 13)}:
        pytest.skip("redepth_pyc intentionally supports CPython 3.12/3.13")
    root = tmp_path_factory.mktemp("harden-dbrc-pyc")
    source = root / "grid_vector.py"
    output = root / "grid_vector.pyc"
    source.write_text(PY_SOURCE, encoding="utf-8")
    py_compile.compile(str(source), cfile=str(output), doraise=True)
    raw = output.read_bytes()
    # marshal is used only on this locally compiled trusted oracle artifact.
    oracle = marshal.loads(raw[16:])
    return raw, oracle


def test_pyc_compiler_and_stdlib_oracle_lock_structure(compiled_pyc) -> None:
    raw, oracle = compiled_pyc
    report = pyc.analyze_pyc(raw)
    assert report.header.version == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert report.root.name == oracle.co_name == "<module>"
    assert report.root.filename == oracle.co_filename
    assert report.root.names == oracle.co_names
    assert report.root.code_size == len(oracle.co_code)

    oracle_child = next(value for value in oracle.co_consts
                        if hasattr(value, "co_name") and value.co_name == "grid_sum")
    child = next(value for value in report.root.children if value.name == "grid_sum")
    assert child.argcount == oracle_child.co_argcount == 1
    assert child.localsplus_names == (
        oracle_child.co_varnames + oracle_child.co_cellvars + oracle_child.co_freevars
    )
    assert child.names == oracle_child.co_names
    assert child.code_size == len(oracle_child.co_code)
    assert any("CSCTF{pyc_vector_lock}" in value for value in report.root.constants)

    oracle_ops = [(row.offset, row.opname) for row in
                  dis.get_instructions(oracle_child, show_caches=True)]
    reported_ops = [(row.physical_offset, row.opname) for row in child.instructions]
    assert reported_ops == oracle_ops


PLAIN_JS = r"""
function table(){
  const values=['alpha','CSCTF{plain_js_vector}'];
  table=function(){return values;}; return table();
}
function decode(index){
  index=index-0x20; const values=table(); let value=values[index]; return value;
}
const answer=decode(0x21);
"""

WEBPACK_FACTORY = (
    'function(module,exports,__webpack_require__){const marker='
    '"CSCTF{webpack_vector}";__webpack_require__(3);}'
)
WEBPACK_JS = f"var __webpack_modules__=({{17:{WEBPACK_FACTORY}}});"


def test_js_documented_plain_wrapper_and_webpack_factory_lock() -> None:
    plain = js.inspect_javascript(PLAIN_JS)
    assert len(plain.string_arrays) == 1
    assert plain.string_arrays[0].raw_values == (
        "alpha", "CSCTF{plain_js_vector}",
    )
    assert [(row.argument, row.array_index, row.value) for row in plain.decoded_calls] == [
        (0x21, 1, "CSCTF{plain_js_vector}"),
    ]

    webpack = js.inspect_javascript(WEBPACK_JS)
    assert len(webpack.webpack_modules) == 1
    module = webpack.webpack_modules[0]
    assert module.module_id == "17"
    assert module.size == len(WEBPACK_FACTORY.encode("utf-8"))
    assert module.sha256 == hashlib.sha256(WEBPACK_FACTORY.encode("utf-8")).hexdigest()
    assert module.strings == ("CSCTF{webpack_vector}",)
    assert module.requires == ("3",)


SWIFT_SOURCE = r"""
struct HardeningMeter {
    let reading: Int
    var label: String
}

enum HardeningState {
    case stable
    case fault(code: Int)
}

@inline(never)
func hardeningDescribe(_ meter: HardeningMeter, _ state: HardeningState) -> String {
    switch state {
    case .stable: return meter.label
    case .fault(let code): return "\(meter.reading)-\(code)"
    }
}

let hardeningMeter = HardeningMeter(reading: 230, label: "grid")
print(hardeningDescribe(hardeningMeter, .fault(code: 7)))
"""


@pytest.fixture(scope="module")
def compiled_swift(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    compiler = shutil.which("swiftc")
    if sys.platform != "darwin" or compiler is None:
        pytest.skip("a Darwin swiftc is required for a Mach-O Swift oracle")
    root = tmp_path_factory.mktemp("harden-dbrc-swift")
    source = root / "HardeningVector.swift"
    output = root / "hardening-vector"
    source.write_text(SWIFT_SOURCE, encoding="utf-8")
    completed = subprocess.run(
        [compiler, "-Onone", "-module-name", "HardeningVector",
         str(source), "-o", str(output)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=90,
    )
    assert completed.returncode == 0, completed.stderr
    raw = output.read_bytes()
    assert raw[:4] in swift._MACHO_MAGICS
    return raw


def test_swift_compiler_oracle_locks_nominal_types_and_fields(compiled_swift) -> None:
    report = swift.extract_swift_metadata(compiled_swift)
    assert report is not None
    assert report["format"] == "mach-o-swift"
    assert report["bits"] == 64
    types = {row["name"]: row for row in report["types"]}
    assert {"HardeningMeter", "HardeningState"} <= set(types)
    assert types["HardeningMeter"]["kind"] == "struct"
    assert types["HardeningState"]["kind"] == "enum"
    meter_fields = {row["name"]: row for row in types["HardeningMeter"]["fields"]}
    assert set(meter_fields) == {"reading", "label"}
    assert meter_fields["reading"]["mangled_type_raw"] == "Si"
    assert meter_fields["label"]["mangled_type_raw"] == "SS"
    assert meter_fields["reading"]["is_var"] is False
    assert meter_fields["label"]["is_var"] is True
    state_fields = {row["name"]: row for row in types["HardeningState"]["fields"]}
    assert set(state_fields) == {"stable", "fault"}
    assert state_fields["stable"]["mangled_type_raw"] is None
    assert state_fields["fault"]["mangled_type_raw"] == "Si4code_t"


def _tiny_go120_table() -> bytes:
    """Write one Go 1.20 pclntab from the published runtime layouts."""
    pointer_size = 8
    header_size = 8 + 8 * pointer_size
    name = b"main.vector\0"
    funcname = header_size
    cutab = 84
    filetab = 88
    pctab = 96
    pcln = 100
    blob = bytearray(160)
    blob[:4] = (0xFFFFFFF1).to_bytes(4, "little")
    blob[4:8] = b"\0\0\x01\x08"
    words = (1, 1, 0x401000, funcname, cutab, filetab, pctab, pcln)
    for index, value in enumerate(words):
        struct.pack_into("<Q", blob, 8 + index * pointer_size, value)
    blob[funcname:funcname + len(name)] = name
    blob[filetab:filetab + 8] = b"main.go\0"
    # functab: (entryoff, funcoff), then terminal entryoff.
    struct.pack_into("<III", blob, pcln, 0, 16, 0x20)
    # runtime._func, with no pcdata/funcdata auxiliary words.
    struct.pack_into(
        "<IiiIIIIIIiBBBB", blob, pcln + 16,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0,
    )
    return bytes(blob)


def test_go_published_layout_vector_locks_header_and_function() -> None:
    report = go.parse_pclntab(_tiny_go120_table())
    assert report.header.magic_hex == "0xfffffff1"
    assert report.header.version == "Go 1.20+"
    assert report.header.pointer_size == 8
    assert report.header.function_count == 1
    assert report.header.text_start == 0x401000
    assert report.header.funcname_offset == 72
    assert report.header.pcln_offset == 100
    assert report.validated_span_end_offset == 160
    assert len(report.functions) == 1
    function = report.functions[0]
    assert function.name == "main.vector"
    assert function.entry_offset == 0
    assert function.end_offset == 0x20
    assert function.nominal_entry_pc == 0x401000
    assert function.nominal_end_pc == 0x401020
    assert function.start_line == 12


def test_real_go_build_oracle_when_toolchain_is_available(tmp_path) -> None:
    compiler = shutil.which("go")
    if compiler is None:
        pytest.skip("Go compiler is not installed; published-layout vector still runs")
    version = subprocess.run(
        [compiler, "version"], check=False, capture_output=True, text=True, timeout=10,
    )
    match = __import__("re").search(r"go(\d+)\.(\d+)", version.stdout)
    if version.returncode or match is None or tuple(map(int, match.groups())) < (1, 20):
        pytest.skip("Go 1.20+ is required")
    source = tmp_path / "main.go"
    output = tmp_path / "grid-go"
    source.write_text(
        "package main\nvar Sink int\n//go:noinline\n"
        "func gridVector(x int) int { return x + 1 }\n"
        "func main() { Sink = gridVector(41) }\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update({"GOPROXY": "off", "GOTOOLCHAIN": "local", "GO111MODULE": "off"})
    built = subprocess.run(
        [compiler, "build", "-trimpath", "-o", str(output), str(source)],
        check=False, capture_output=True, text=True, timeout=90, env=environment,
    )
    assert built.returncode == 0, built.stderr
    report = go.analyze_go(output.read_bytes())
    names = {function.name for function in report.functions}
    assert "main.main" in names
    assert "main.gridVector" in names


def _clean_or_declared(function, value, declared) -> None:
    try:
        function(value)
    except BaseException as exc:  # Deliberately catches leaked SystemExit too.
        assert isinstance(exc, declared), f"leaked {type(exc).__name__}: {exc}"


def _deterministic_random_blobs(seed: int) -> list[bytes]:
    rng = random.Random(seed)
    return [bytes(rng.randrange(256) for _ in range(length))
            for length in (0, 1, 3, 7, 16, 31, 127, 511)]


def _bit_flips(data: bytes, seed: int, count: int = 24) -> list[bytes]:
    rng = random.Random(seed)
    output: list[bytes] = []
    for _ in range(count):
        mutated = bytearray(data)
        offset = rng.randrange(len(mutated))
        mutated[offset] ^= 1 << rng.randrange(8)
        output.append(bytes(mutated))
    return output


def test_pyc_fail_closed_fuzz_and_downscaled_oversize(compiled_pyc, monkeypatch) -> None:
    valid, _ = compiled_pyc
    cases = _deterministic_random_blobs(0xD0B1)
    cases += [valid[:stop] for stop in (1, 4, 8, 15, 16, len(valid) // 2, len(valid) - 1)]
    cases += _bit_flips(valid, 0xD0B2)
    for value in cases:
        _clean_or_declared(pyc.analyze_pyc, value, pyc.RedepthPycError)
    monkeypatch.setattr(pyc, "MAX_INPUT", 32)
    with pytest.raises(pyc.RedepthPycError):
        pyc.analyze_pyc(b"X" * 33)


def test_js_fail_closed_fuzz_and_downscaled_oversize(monkeypatch) -> None:
    valid = PLAIN_JS.encode("utf-8")
    cases = _deterministic_random_blobs(0xD0B3)
    cases += [b"\xff\xfe", valid[:17], valid[:len(valid) // 2], valid[:-1]]
    cases += _bit_flips(valid, 0xD0B4)
    for value in cases:
        _clean_or_declared(js.inspect_javascript, value, js.RedepthJSError)
    monkeypatch.setattr(js, "MAX_SOURCE", 32)
    with pytest.raises(js.RedepthJSError):
        js.inspect_javascript("X" * 33)


def test_swift_fail_closed_fuzz_and_downscaled_oversize(compiled_swift, monkeypatch) -> None:
    cases = _deterministic_random_blobs(0xD0B5)
    cases += [compiled_swift[:stop] for stop in
              (1, 4, 8, 16, 28, len(compiled_swift) // 2, len(compiled_swift) - 1)]
    cases += _bit_flips(compiled_swift, 0xD0B6)
    for value in cases:
        _clean_or_declared(swift.extract_swift_metadata, value, swift.SwiftMetadataError)
    monkeypatch.setattr(swift, "MAX_INPUT", 64)
    with pytest.raises(swift.SwiftMetadataError):
        swift.extract_swift_metadata(b"X" * 65)


def test_go_fail_closed_fuzz_and_downscaled_oversize(monkeypatch) -> None:
    valid = _tiny_go120_table()
    cases = _deterministic_random_blobs(0xD0B7)
    cases += [valid[:stop] for stop in (1, 4, 7, 8, 40, 72, len(valid) - 1)]
    cases += _bit_flips(valid, 0xD0B8)
    for value in cases:
        _clean_or_declared(go.parse_pclntab, value, go.RedepthGoError)
        _clean_or_declared(go.analyze_go, value, go.RedepthGoError)
    monkeypatch.setattr(go, "MAX_INPUT", 64)
    with pytest.raises(go.RedepthGoError):
        go.parse_pclntab(b"X" * 65)


@pytest.mark.parametrize(
    ("function", "value", "declared"),
    [
        (pyc.analyze_pyc, bytearray(b"x"), pyc.RedepthPycError),
        (js.inspect_javascript, object(), js.RedepthJSError),
        (swift.extract_swift_metadata, object(), swift.SwiftMetadataError),
        (go.parse_pclntab, bytearray(b"x"), go.RedepthGoError),
    ],
)
def test_wrong_type_never_leaks_stdlib_exception(function, value, declared) -> None:
    with pytest.raises(declared):
        function(value)
