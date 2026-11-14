"""Deterministic tests for inert concolic/taint plan generation."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import concolic_taint_plans as plans  # noqa: E402


def _spec(**updates):
    value = {
        "input_name": "checker.bin",
        "architecture": "amd64",
        "mode": "stdin",
        "seed": "CTF{seed}",
        "symbolic_offsets": [4, 5, 6, 7],
        "find": ["0x401100"],
        "avoid": [0x401200],
        "taint_sinks": [0x401300],
        "input_address": "0x70000000",
        "trace": [0x401000, 0x401004],
        "max_steps": 1234,
        "max_active": 32,
        "solution_limit": 3,
        "timeout_seconds": 40,
    }
    value.update(updates)
    return value


def test_matrix_is_canonical_deterministic_and_sandbox_locked():
    matrix = plans.build_analysis_matrix(_spec(), engines=("triton", "angr"))
    assert [item.engine for item in matrix] == ["angr-concolic", "triton-taint"]
    assert matrix == plans.build_analysis_matrix(_spec())
    for plan in matrix:
        assert plan.network == "none"
        assert plan.read_only_root is True
        assert plan.drop_capabilities == ("ALL",)
        assert plan.artifact_execution_expected is True
        assert plan.image == "csctf-analysis:1"
        assert plan.image_build_required is True
        assert plan.runtime_requirements
        assert plan.timeout_seconds == 40
        assert json.loads(plan.manifest)["sandbox_required"] is True
        assert not set(plan.expected_outputs) & {name for name, _content in plan.generated_files}
    rendered = json.loads(plans.render_plan_manifest(matrix))
    assert [item["engine"] for item in rendered] == ["angr-concolic", "triton-taint"]


def test_angr_plan_starts_from_seed_and_symbolizes_only_selected_offsets():
    plan = plans.build_angr_concolic_plan(_spec(mode="file"))
    source = plan.generated_files[0][1]
    compile(source, "<r5d-angr-concolic>", "exec")
    assert "SEED = bytes.fromhex('4354467b736565647d')" in source
    assert "SYMBOLIC_OFFSETS = (4, 5, 6, 7)" in source
    assert "symbolic.get(index, claripy.BVV(byte, 8))" in source
    assert "angr.SimFile(INPUT_FILE" in source
    assert "Tracer(trace=list(TRACE)" in source
    assert "MAX_ACTIVE = 32" in source
    assert "while manager.active" in source
    assert "eval_upto(mixed, SOLUTION_LIMIT + 1" in source
    assert "'ambiguous': ambiguous" in source
    assert "'sink_data_taint_analyzed': False" in source
    assert plan.argv == ("python3", "/plan/r5d_angr_concolic.py")
    assert plan.expected_outputs == ("r5d_angr_concolic.json",)


def test_angr_raw_blob_profile_is_literal_and_reviewable():
    plan = plans.build_angr_concolic_plan(_spec(
        base_address="0x400000", entrypoint="0x401000", mode="argv"
    ))
    source = plan.generated_files[0][1]
    compile(source, "<r5d-angr-blob>", "exec")
    assert "'backend': 'blob'" in source
    assert "'arch': 'AMD64'" in source
    assert "'base_addr': 4194304" in source
    assert "full_init_state(args=[BINARY, mixed])" in source


def test_triton_plan_consumes_only_a_bounded_saved_trace_in_docker():
    plan = plans.build_triton_taint_plan(
        _spec(architecture="arm"), trace_name="saved-trace.json", output_name="taint.json"
    )
    source = plan.generated_files[0][1]
    compile(source, "<r5d-triton-taint>", "exec")
    assert "TRACE_PATH = '/work/saved-trace.json'" in source
    assert "ctx.setArchitecture(ARCH.ARM32)" in source
    assert "handle.read(MAX_TRACE_BYTES + 1)" in source
    assert "set(trace) != required" in source
    assert "trace['contract_version'] != 1" in source
    assert "trace['reconciliation'] != 'pre-instruction'" in source
    assert "address + len(blob) > (1 << 64)" in source
    assert "not 1 <= len(instructions) <= MAX_INSTRUCTIONS" in source
    assert "not 2 <= len(opcode_hex) <= 64" in source
    assert "ctx.taintMemory(memory)" in source
    assert "instruction.getSymbolicExpressions()" in source
    assert "ctx.isRegisterTainted(register)" in source
    assert "ctx.isMemoryTainted(memory)" in source
    assert "ctx.processing(instruction)" in source
    assert plan.expected_outputs == ("taint.json",)
    assert json.loads(plan.manifest)["trace_name"] == "saved-trace.json"
    assert json.loads(plan.manifest)["trace_contract"] == 1


def test_angr_trace_preserves_order_and_loop_repetitions():
    value = plans.ConcolicSpec.from_mapping(_spec(trace=[30, 10, 30, 20]))
    assert value.trace == (30, 10, 30, 20)
    source = plans.build_angr_concolic_plan(value).generated_files[0][1]
    assert "TRACE = (30, 10, 30, 20)" in source


def test_default_matrix_selects_only_compatible_engines():
    find_only = _spec(taint_sinks=[], input_address=None)
    assert [item.engine for item in plans.build_analysis_matrix(find_only)] == ["angr-concolic"]
    with pytest.raises(ValueError, match="input_address"):
        plans.build_triton_taint_plan(_spec(input_address=None))


@pytest.mark.parametrize(
    "update,match",
    [
        ({"input_name": "bad/name"}, "unsafe"),
        ({"architecture": "sparc"}, "architecture"),
        ({"mode": "environment"}, "mode"),
        ({"seed": b""}, "seed"),
        ({"symbolic_offsets": []}, "symbolic_offsets"),
        ({"symbolic_offsets": [4, 4]}, "distinct"),
        ({"symbolic_offsets": [100]}, "outside"),
        ({"find": [], "taint_sinks": []}, "at least one"),
        ({"find": [1], "avoid": [1]}, "overlap"),
        ({"find": ["__import__('os')"]}, "literal"),
        ({"base_address": 0x4000}, "together"),
        ({"base_address": 0x4000, "entrypoint": 0x3000}, "precede"),
        ({"input_address": (1 << 64) - 1}, "address space"),
        ({"max_steps": 0}, "max_steps"),
    ],
)
def test_spec_validation_rejects_ambiguous_or_unbounded_values(update, match):
    with pytest.raises(ValueError, match=match):
        plans.ConcolicSpec.from_mapping(_spec(**update))


def test_hex_seed_unknown_keys_names_and_engine_lists_are_strict():
    value = plans.ConcolicSpec.from_mapping({
        **_spec(), "seed": None, "seed_hex": "00ff41", "symbolic_offsets": [0]
    })
    assert value.seed == b"\x00\xffA"
    assert json.loads(plans.render_spec_manifest(value, "triton"))["seed_hex"] == "00ff41"
    with pytest.raises(ValueError, match="choose"):
        plans.ConcolicSpec.from_mapping({**_spec(), "seed_hex": "00"})
    with pytest.raises(ValueError, match="unknown"):
        plans.ConcolicSpec.from_mapping({**_spec(), "typo": 1})
    with pytest.raises(ValueError, match="unsafe"):
        plans.build_triton_taint_plan(_spec(), trace_name="x;touch")
    with pytest.raises(ValueError, match="taint sink"):
        plans.build_triton_taint_plan(_spec(taint_sinks=[]))
    with pytest.raises(ValueError, match="distinct"):
        plans.build_analysis_matrix(_spec(), engines=("angr", "angr"))
    with pytest.raises(ValueError, match="unsupported"):
        plans.build_analysis_matrix(_spec(), engines=("qiling",))
    with pytest.raises(ValueError, match="engine"):
        plans.render_spec_manifest(_spec(), "other")
    with pytest.raises(ValueError, match="only for Triton"):
        plans.render_spec_manifest(_spec(), "angr", trace_name="trace.json")


def test_direct_dataclass_instances_are_revalidated():
    invalid = plans.ConcolicSpec(
        input_name="x", architecture="amd64", mode="stdin", seed=b"x",
        symbolic_offsets=(2,), find=(1,),
    )
    with pytest.raises(ValueError, match="outside"):
        plans.normalize_spec(invalid)


def test_module_ast_has_no_runtime_engine_transport_or_execution_surface():
    source = (REPO / "solvers" / "binary" / "concolic_taint_plans.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported & {
        "angr", "claripy", "triton", "subprocess", "socket", "requests", "httpx", "os"
    }
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"exec", "eval", "compile", "open", "__import__"}

