"""Synthetic tests for offline reversing plans and static helpers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import reverse_depth as rev  # noqa: E402


def test_angr_harness_is_bounded_source_only_and_compiles():
    spec = {
        "binary": "/chal/checker",
        "mode": "stdin",
        "length": 8,
        "find": ["0x401234"],
        "avoid": ["0x401250"],
        "prefix": "CTF{",
        "suffix": "}",
        "alphabet": "printable",
    }
    source = rev.build_angr_harness(spec)
    compile(source, "<generated-angr-harness>", "exec")
    assert "angr.Project" in source
    assert "auto_load_libs=False" in source
    assert "manager.explore" in source
    assert "0x401234" not in source  # normalized integer literal, no caller expression survives
    assert "4198964" in source
    assert "eval_upto(symbolic, 2" in source

    nul = rev.build_angr_harness({"binary": "/chal/x", "mode": "argv", "length": 4,
                                  "find": [1], "alphabet": [65, 66], "null_terminate": True})
    assert "symbolic.get_byte(3) == 0" in nul


def test_angr_spec_rejects_unbounded_or_expression_addresses():
    with pytest.raises(ValueError):
        rev.build_angr_harness({"length": 999999, "find": [1]})
    with pytest.raises(ValueError):
        rev.build_angr_harness({"length": 4, "find": ["__import__('os')"]})


def test_opaque_predicate_and_flattening_notes():
    asm = """
401000: xor eax, eax
401002: test eax, eax
401004: jne 401100
401006: cmp ebx, ebx
401008: je 401200
40100a: cmp eax, 1
40100d: jne 401020
40100f: cmp eax, 2
401012: je 401030
401014: cmp eax, 3
401017: je 401040
401019: cmp eax, 4
40101c: je 401050
40101e: jmp *rax
"""
    result = rev.analyze_control_flow(asm)
    assert len(result["opaque_predicates"]) == 2
    reasons = {item["reason"] for item in result["opaque_predicates"]}
    assert "xor-self zeroes the tested register" in reasons
    assert "comparison of a value with itself has a constant result" in reasons
    assert any(item["kind"] == "indirect-dispatch" for item in result["flattening_notes"])
    assert any(item["kind"] == "state-dispatch" for item in result["flattening_notes"])


def test_vm_handler_mapper_recovers_opcode_and_semantics():
    asm = """
00001000 <vm_op_01>:
1000: pop rax
1001: pop rbx
1002: add rax, rbx
1004: push rax
1005: ret
00001100 <handler_op_02>:
1100: cmp rax, rbx
1102: jne 1200
1104: ret
"""
    result = rev.map_vm_handlers(asm)
    assert result["handler_count"] == 2
    first = result["handlers"][0]
    assert first["opcode"] == 1
    assert "arithmetic-add" in first["semantics"]
    assert "stack" in first["semantics"]
    assert "return-halt" in first["semantics"]
    second = result["handlers"][1]
    assert second["opcode"] == 2
    assert "compare" in second["semantics"] and "branch" in second["semantics"]


def test_go_and_rust_symbol_type_leads():
    rust = b"_ZN4core3ptr13drop_in_place17h0123456789abcdefE"
    data = (b"\x7fELF" + b"\x00" * 64
            + b"github.com/chronos/pkg.(*Checker).Verify\x00"
            + rust + b"\x00type:.eq.github.com/chronos/pkg.Token\x00")
    report = rev.recover_go_rust_symbols(data)
    assert any("Checker" in item for item in report["go_symbols"])
    item = next(item for item in report["rust_symbols"] if item["raw"].encode() == rust)
    assert item["demangled"] == "core::ptr::drop_in_place"
    assert any(value.startswith("type:.eq.") for value in report["type_leads"])


def test_guarded_cli_json_and_garbage(tmp_path, capsys):
    spec = tmp_path / "angr.json"
    spec.write_text(json.dumps({"binary": "/chal/x", "length": 3, "find": [1]}), encoding="utf-8")
    assert rev.main(["angr", str(spec), "--json"]) == 0
    assert "angr.Project" in json.loads(capsys.readouterr().out)["harness"]

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert rev.main(["angr", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("reverse_depth: ")
    assert "Traceback" not in captured.err

