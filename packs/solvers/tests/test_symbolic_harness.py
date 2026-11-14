"""Tests for source-only, bounded r5d symbolic harness generation."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import reversing_static as static  # noqa: E402
import symbolic_harness as symbolic  # noqa: E402


def _elf() -> bytes:
    data = bytearray(128)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 24, 0x401000)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data)


def test_angr_source_is_deterministic_bounded_and_compilable():
    spec = {
        "binary": "/chal/checker",
        "mode": "stdin",
        "length": 10,
        "find": ["0x401234", 0x401234],
        "avoid": ["0x401250"],
        "prefix": "CSCTF{",
        "suffix": "}",
        "alphabet": "printable",
        "max_steps": 1234,
        "max_active": 32,
        "solution_limit": 2,
    }
    source = symbolic.build_angr_harness(spec)
    assert source == symbolic.build_angr_harness(spec)
    compile(source, "<r5d-angr>", "exec")
    assert "angr.Project" in source
    assert "'auto_load_libs': False" in source
    assert "MAX_STEPS = 1234" in source
    assert "MAX_ACTIVE = 32" in source
    assert "while manager.active" in source
    assert "eval_upto(symbolic, SOLUTION_LIMIT + 1" in source
    assert "state.solver.add(symbolic.get_byte(0) == 67)" in source
    assert "state.solver.add(symbolic.get_byte(9) == 125)" in source
    assert "4198964" in source
    assert "0x401234" not in source


def test_literal_validation_blocks_expression_addresses_and_unbounded_specs():
    baseline = {"length": 4, "find": [1]}
    with pytest.raises(ValueError, match="non-literal"):
        symbolic.SymbolicSpec.from_mapping({**baseline, "find": ["__import__('os')"]})
    with pytest.raises(ValueError, match="length"):
        symbolic.SymbolicSpec.from_mapping({"length": 4097, "find": [1]})
    with pytest.raises(ValueError, match="prefix"):
        symbolic.SymbolicSpec.from_mapping({"length": 2, "find": [1], "prefix": "long"})
    with pytest.raises(ValueError, match="max_steps"):
        symbolic.SymbolicSpec.from_mapping({**baseline, "max_steps": 0})
    with pytest.raises(ValueError, match="control"):
        symbolic.SymbolicSpec.from_mapping({**baseline, "binary": "/tmp/x\nimport os"})
    with pytest.raises(ValueError, match="64-bit"):
        symbolic.SymbolicSpec.from_mapping({"length": 2, "find": [True], "avoid": []})
    with pytest.raises(ValueError, match="overlap"):
        symbolic.SymbolicSpec.from_mapping({"length": 2, "find": [1], "avoid": [1]})
    with pytest.raises(ValueError, match="unknown"):
        symbolic.SymbolicSpec.from_mapping({**baseline, "max_stepz": 10})
    leading_zero = symbolic.SymbolicSpec.from_mapping({"length": 2, "find": ["0001"]})
    assert leading_zero.find == (1,)


def test_path_text_is_quoted_as_data_not_source_expression():
    path = "/chal/x'; __import__('os').system('false'); #"
    source = symbolic.build_angr_harness({"binary": path, "length": 2, "find": [1]})
    compile(source, "<quoted-r5d-angr>", "exec")
    expected_assignment = f"BINARY = {path!r}"
    assert expected_assignment in source
    assert source.count("__import__") == 1


def test_file_and_blob_modes_emit_static_loader_configuration():
    file_source = symbolic.build_angr_harness({
        "binary": "/chal/checker", "mode": "file", "file_path": "/tmp/input.bin",
        "length": 4, "find": [0x1000], "alphabet": [0, 65, 66],
    })
    compile(file_source, "<file-harness>", "exec")
    assert "angr.SimFile(FILE_PATH" in file_source
    assert "state.fs.insert(FILE_PATH" in file_source

    blob = {
        "binary": "/chal/raw.bin", "length": 8, "find": [0x4010],
        "blob_arch": "amd64", "base_addr": 0x4000, "entry_addr": 0x4000,
        "state_factory": "entry", "alphabet": "bytes",
    }
    blob_source = symbolic.build_angr_harness(blob)
    assert "'backend': 'blob'" in blob_source
    assert "'arch': 'AMD64'" in blob_source
    assert "entry_state" in blob_source
    with pytest.raises(ValueError, match="requires"):
        symbolic.SymbolicSpec.from_mapping({
            "length": 2, "find": [1], "blob_arch": "amd64", "base_addr": 0
        })
    with pytest.raises(ValueError, match="precede"):
        symbolic.SymbolicSpec.from_mapping({
            "length": 2, "find": [1], "blob_arch": "amd64",
            "base_addr": 0x4000, "entry_addr": 0x3FFF,
        })


def test_manifest_is_canonical_and_omits_raw_prefix_text():
    spec = {"binary": "/chal/x", "length": 5, "find": [2, 1],
            "prefix_hex": "00ff", "suffix": "}", "alphabet": "alnum"}
    first = symbolic.render_manifest(spec)
    assert first == symbolic.render_manifest(spec)
    parsed = json.loads(first)
    assert parsed["find"] == [1, 2]
    assert parsed["prefix_hex"] == "00ff"
    assert parsed["suffix_hex"] == "7d"
    assert bytes.fromhex(parsed["alphabet_hex"]) == bytes(
        sorted(set(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"))
    )
    assert parsed["sandbox_required"] is True
    assert "prefix\"" not in first


def test_static_report_integration_allows_native_and_rejects_managed_vm_formats():
    report = static.analyze_static(_elf())
    spec = symbolic.spec_from_static_report(
        report, binary="/chal/native", length=6, find=[0x401234], prefix="CTF{"
    )
    assert spec.architecture_hint == "amd64"
    source, manifest = symbolic.build_harness_from_static_report(
        report, binary="/chal/native", length=6, find=[0x401234], prefix="CTF{"
    )
    compile(source, "<report-harness>", "exec")
    assert json.loads(manifest)["architecture_hint"] == "amd64"

    managed = {"metadata": {"format": "pe", "architecture": "amd64", "managed": True}}
    with pytest.raises(ValueError, match="managed"):
        symbolic.spec_from_static_report(managed, binary="/chal/x", length=2, find=[1])
    wasm = {"metadata": {"format": "wasm", "architecture": "wasm32", "managed": False}}
    with pytest.raises(ValueError, match="not supported"):
        symbolic.spec_from_static_report(wasm, binary="/chal/x", length=2, find=[1])
    ebpf = {"metadata": {"format": "elf", "architecture": "ebpf", "managed": False}}
    with pytest.raises(ValueError, match="eBPF"):
        symbolic.spec_from_static_report(ebpf, binary="/chal/x", length=2, find=[1])
    with pytest.raises(ValueError, match="derived"):
        symbolic.spec_from_static_report(
            report, binary="/chal/x", length=2, find=[1], architecture_hint="x86"
        )


def test_direct_dataclass_instances_are_revalidated():
    invalid = symbolic.SymbolicSpec(binary="/x", mode="stdin", length=0, find=(1,))
    with pytest.raises(ValueError, match="length"):
        symbolic.normalize_spec(invalid)
