"""Static anti-debug/VM/analysis evidence and declarative-note tests."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import anti_analysis as anti  # noqa: E402


def test_windows_debug_and_vm_markers_are_evidence_ordered():
    saved = (
        b"MZ IsDebuggerPresent CheckRemoteDebuggerPresent "
        b"NtQueryInformationProcess ProcessDebugPort VMXh VMware"
    )
    report = anti.analyze_anti_analysis(saved)
    identifiers = [row.identifier for row in report.findings]
    assert identifiers == ["win-debugger-api", "win-native-debug-query", "vmware-fingerprint"]
    assert report.score > 0
    assert all(row.offsets == tuple(sorted(row.offsets)) for row in report.findings)
    assert report.to_dict()["defeat_notes"][0]["precondition"].startswith("Trace data flow")


def test_require_all_rules_prevent_single_marker_false_positives():
    lone = anti.analyze_anti_analysis(b"TracerPid alone; product_name alone; generic CRC32 parser")
    assert not any(row.identifier in {
        "linux-tracerpid", "dmi-fingerprint", "self-integrity", "self-integrity-crc32"
    } for row in lone.findings)
    paired = anti.analyze_anti_analysis(b"/proc/self/status\nTracerPid:\t0")
    finding = next(row for row in paired.findings if row.identifier == "linux-tracerpid")
    assert finding.confidence == 98


def test_saved_disassembly_patterns_cover_timing_cpuid_peb_and_traps():
    text = """
401000: rdtsc
401002: cpuid
401004: mov rax, gs:[0x60]
40100b: cmp byte ptr [rax + 2], 0
401010: int3
"""
    report = anti.analyze_anti_analysis(text)
    identifiers = {row.identifier for row in report.findings}
    assert {"x86-rdtsc", "x86-cpuid", "peb-being-debugged", "trap-probe"} <= identifiers
    assert anti.findings_by_category(report, "timing")[0].identifier == "x86-rdtsc"


def test_defeat_notes_are_declarative_and_integrity_aware():
    report = anti.analyze_anti_analysis(b"self checksum CRC32 checksum mismatch")
    finding = next(row for row in report.findings if row.category == "integrity")
    note = next(row for row in report.defeat_notes if row.finding == finding.identifier)
    assert "Identify the hashed byte ranges" in note.declarative_action
    assert "Do not patch" in note.risk
    assert not any(token in note.declarative_action for token in ("0x90", "write bytes", "execute"))
    assert {row.identifier for row in report.findings if row.category == "integrity"} == {
        "self-integrity", "self-integrity-crc32"
    }


def test_determinism_categories_and_invalid_category():
    value = b"ptrace PTRACE_TRACEME x64dbg QueryPerformanceCounter"
    first = anti.analyze_anti_analysis(value)
    assert first == anti.analyze_anti_analysis(value)
    assert {row.category for row in first.findings} >= {"anti-debug", "tool-detection", "timing"}
    with pytest.raises(ValueError, match="unsupported"):
        anti.findings_by_category(first, "unknown")


def test_caps_types_and_ast_safety(monkeypatch):
    with pytest.raises(TypeError, match="bytes or text"):
        anti.analyze_anti_analysis(bytearray(b"x"))  # type: ignore[arg-type]
    monkeypatch.setattr(anti, "MAX_INPUT", 3)
    with pytest.raises(anti.AntiAnalysisInputError, match="cap"):
        anti.analyze_anti_analysis("four")
    tree = ast.parse((REPO / "solvers" / "binary" / "anti_analysis.py").read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not imports & {"subprocess", "socket", "requests", "marshal", "pickle", "importlib"}
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}
