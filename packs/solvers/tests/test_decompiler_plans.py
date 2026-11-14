"""Tests for source/argv-only decompiler orchestration plans."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import decompiler_plans as plans  # noqa: E402


def test_default_matrix_is_canonical_deterministic_and_docker_locked():
    matrix = plans.build_decompiler_matrix("challenge.bin", engines=("retdec", "ghidra", "angr"))
    assert [plan.engine for plan in matrix] == ["ghidra", "angr", "retdec"]
    assert matrix == plans.build_decompiler_matrix("challenge.bin")
    for plan in matrix:
        assert plan.network == "none"
        assert plan.read_only_root is True
        assert plan.drop_capabilities == ("ALL",)
        assert isinstance(plan.argv, tuple)
        assert all(isinstance(item, str) for item in plan.argv)
    assert json.loads(plans.render_plan_manifest(matrix))[0]["engine"] == "ghidra"


def test_generated_ghidra_and_angr_sources_are_fixed_and_compilable():
    ghidra = plans.build_ghidra_plan("sample.exe")
    assert ghidra.argv[0].endswith("analyzeHeadless")
    assert ghidra.argv[-1] == "-deleteProject"
    ghidra_source = ghidra.generated_files[0][1]
    compile(ghidra_source, "<r5d-ghidra-export>", "exec")
    assert "DecompInterface" in ghidra_source
    assert "len(rows) < 10000" in ghidra_source
    assert "total_text < 67108864" in ghidra_source
    assert "decompiled[:min(1048576, remaining)]" in ghidra_source

    angr = plans.build_angr_plan("sample.exe")
    angr_source = angr.generated_files[0][1]
    compile(angr_source, "<r5d-angr-cfg>", "exec")
    assert "CFGFast" in angr_source
    assert "'auto_load_libs': False" in angr_source
    assert "if len(blocks) >= 4096" in angr_source
    assert angr.argv == (
        "python3", "/plan/r5d_angr_cfg.py", "/work/sample.exe", "/out/r5d_angr.json"
    )


def test_raw_profiles_flow_to_each_engine_without_shell_text():
    profile = {
        "format": "raw", "architecture": "amd64", "bits": 64,
        "endian": "little", "base_address": "0x400000", "entrypoint": "0x401000",
    }
    matrix = plans.build_decompiler_matrix("firmware.bin", profile)
    ghidra, angr, retdec = matrix
    assert "BinaryLoader" in ghidra.argv
    assert "x86:LE:64:default" in ghidra.argv
    assert "0x400000" in ghidra.argv
    assert "'backend': 'blob'" in angr.generated_files[0][1]
    assert "'entry_point': 4198400" in angr.generated_files[0][1]
    assert retdec.argv[-1] == "/work/firmware.bin"
    assert ("--mode", "raw") == retdec.argv[retdec.argv.index("--mode"):retdec.argv.index("--mode") + 2]


def test_profile_and_name_validation_rejects_ambiguous_or_injected_values():
    with pytest.raises(ValueError, match="require"):
        plans.ArtifactProfile.from_mapping({"format": "raw", "architecture": "amd64"})
    with pytest.raises(ValueError, match="precede"):
        plans.ArtifactProfile.from_mapping({
            "format": "raw", "architecture": "x86", "bits": 32,
            "base_address": 0x5000, "entrypoint": 0x4000,
        })
    with pytest.raises(ValueError, match="unknown"):
        plans.ArtifactProfile.from_mapping({"format": "elf", "arch": "x86"})
    with pytest.raises(ValueError, match="inconsistent"):
        plans.ArtifactProfile.from_mapping({"format": "elf", "architecture": "amd64", "bits": 32})
    with pytest.raises(ValueError, match="unsafe"):
        plans.build_angr_plan("x;touch pwned")
    with pytest.raises(ValueError, match="unsafe"):
        plans.build_ghidra_plan("x", project_name="bad project")
    with pytest.raises(ValueError, match="timeout"):
        plans.build_retdec_plan("x", timeout_seconds=0)
    with pytest.raises(ValueError, match="distinct"):
        plans.build_decompiler_matrix("x", engines=("angr", "angr"))
    with pytest.raises(ValueError, match="contain"):
        plans.build_decompiler_matrix("x", engines=())


def test_plan_manifest_and_sources_do_not_depend_on_mapping_order():
    left = {"format": "elf", "architecture": "amd64", "bits": 64}
    right = {"bits": 64, "architecture": "amd64", "format": "elf"}
    left_plans = plans.build_decompiler_matrix("a.bin", left)
    right_plans = plans.build_decompiler_matrix("a.bin", right)
    assert left_plans == right_plans
    assert plans.render_plan_manifest(left_plans) == plans.render_plan_manifest(right_plans)


def test_module_ast_cannot_spawn_or_load_decompiler_packages():
    source = (REPO / "solvers" / "binary" / "decompiler_plans.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported & {"subprocess", "os", "angr", "ghidra", "requests", "socket"}
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"exec", "eval", "compile", "open", "__import__"}
