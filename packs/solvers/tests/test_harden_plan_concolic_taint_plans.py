"""Inert plan contracts: literal AST inspection and independent manifest values.

Only ast.parse examines generated Python; nothing generated is executed.
Sources: docs.python.org/3/library/ast.html, angr core-concepts/states.html,
triton-library.github.io/documentation/doxygen/namespacetriton_1_1arch.html.
"""
import ast
import builtins
from dataclasses import replace
import json
import os
from pathlib import Path
import random
import socket
import subprocess

import pytest

import concolic_taint_plans as engine


def spec(**changes):
    value = {
        "input_name": "fixture.bin", "architecture": "amd64", "mode": "stdin",
        "seed_hex": "43534354467b00ff7d", "symbolic_offsets": [7, 2, 0],
        "find": ["0x601120", 0x601100, 0x601100], "avoid": ["6296064"],
        "taint_sinks": [0x601300], "trace": [0x601020, 0x601010, 0x601020],
        "input_address": "0x71234000", "base_address": "0x600000", "entrypoint": "0x601000",
        "max_steps": 73, "max_active": 5, "solution_limit": 2, "timeout_seconds": 11,
    }
    value.update(changes)
    return value


def expected_manifest(which):
    result = {
        "architecture": "amd64", "avoid": [0x601200], "base_address": 0x600000,
        "engine": which, "entrypoint": 0x601000, "find": [0x601100, 0x601120],
        "input_address": 0x71234000, "input_name": "fixture.bin",
        "limits": {"active_states": 5, "solutions": 2, "steps_or_instructions": 73, "timeout_seconds": 11},
        "mode": "stdin", "network": "none", "sandbox_required": True,
        "seed_hex": "43534354467b00ff7d", "symbolic_offsets": [0, 2, 7],
        "taint_sinks": [0x601300], "trace": [0x601020, 0x601010, 0x601020],
    }
    if which == "triton":
        result.update(trace_name="r5d_instruction_trace.json", trace_contract=1, trace_reconciliation="pre-instruction")
    return result


def inert_call(monkeypatch, function, *args, **kwargs):
    original_import = builtins.__import__
    def denied(*args, **kwargs):
        raise AssertionError("plan construction accessed external state or executed code")
    def import_guard(name, *args, **kwargs):
        if name.split(".")[0] in {"angr", "claripy", "triton", "unicorn", "qiling"}:
            denied()
        return original_import(name, *args, **kwargs)
    with monkeypatch.context() as context:
        context.setattr(builtins, "__import__", import_guard)
        context.setattr(builtins, "open", denied)
        context.setattr(builtins, "eval", denied)
        context.setattr(builtins, "exec", denied)
        context.setattr(os, "open", denied)
        context.setattr(os, "system", denied)
        context.setattr(Path, "read_bytes", denied)
        context.setattr(Path, "read_text", denied)
        context.setattr(socket, "socket", denied)
        context.setattr(socket, "create_connection", denied)
        context.setattr(subprocess, "Popen", denied)
        return function(*args, **kwargs)


def constants(tree):
    return {node.targets[0].id: node.value for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}


def assert_literal(node, expected):
    # Compare syntax trees, without literal_eval/compile/eval/exec.
    assert ast.dump(node) == ast.dump(ast.parse(repr(expected), mode="eval").body)


def test_normalizer_literal_addresses_seed_offsets_and_dataclass(monkeypatch):
    value = inert_call(monkeypatch, engine.normalize_spec, spec())
    assert value.seed == b"CSCTF{\x00\xff}"
    assert value.symbolic_offsets == (0, 2, 7)
    assert value.find == (0x601100, 0x601120)
    assert value.avoid == (0x601200,)
    assert value.trace == (0x601020, 0x601010, 0x601020)
    assert value.input_address == 0x71234000
    assert (value.base_address, value.entrypoint) == (0x600000, 0x601000)
    assert value == engine.ConcolicSpec.from_mapping(spec())
    assert value == engine.normalize_spec(value)
    unicode_seed = engine.normalize_spec(spec(seed_hex=None, seed="AéZ", symbolic_offsets=[1, 2]))
    assert unicode_seed.seed == b"A\xc3\xa9Z" and unicode_seed.symbolic_offsets == (1, 2)


@pytest.mark.parametrize("which", ["angr", "triton"])
def test_spec_manifest_exact_independent_schema(monkeypatch, which):
    raw = inert_call(monkeypatch, engine.render_spec_manifest, spec(), which)
    expected = expected_manifest(which)
    assert json.loads(raw) == expected
    assert raw == json.dumps(expected, sort_keys=True, separators=(",", ":"))
    assert raw == engine.render_spec_manifest(spec(), which)


@pytest.mark.parametrize("mode", ["stdin", "argv", "file"])
def test_angr_plan_literal_ast_and_mode(mode, monkeypatch):
    value = spec(mode=mode)
    plan = inert_call(monkeypatch, engine.build_angr_concolic_plan, value, output_name="answer.json")
    assert plan == engine.build_angr_concolic_plan(value, output_name="answer.json")
    assert plan.argv == ("python3", "/plan/r5d_angr_concolic.py")
    assert plan.expected_outputs == ("answer.json",)
    files = dict(plan.generated_files)
    tree = ast.parse(files["r5d_angr_concolic.py"])
    nodes = constants(tree)
    for name, expected in {"BINARY": "/work/fixture.bin", "SYMBOLIC_OFFSETS": (0,2,7), "FIND": (0x601100,0x601120),
                           "AVOID": (0x601200,), "TAINT_SINKS": (0x601300,), "TRACE": (0x601020,0x601010,0x601020),
                           "MAX_STEPS":73,"MAX_ACTIVE":5,"SOLUTION_LIMIT":2}.items():
        assert_literal(nodes[name], expected)
    assert isinstance(nodes["SEED"], ast.Call)
    assert ast.unparse(nodes["SEED"].func) == "bytes.fromhex"
    assert_literal(nodes["SEED"].args[0], "43534354467b00ff7d")
    assert_literal(nodes["project"].keywords[0].value, {"auto_load_libs":False, "main_opts": {
        "backend":"blob", "arch":"AMD64", "base_addr":0x600000,"entry_point":0x601000}})
    state = nodes["state"]
    assert ast.unparse(state.func) == "project.factory.full_init_state"
    assert [kw.arg for kw in state.keywords] == (["stdin"] if mode == "stdin" else ["args"])
    if mode in ("argv", "file"):
        assert ast.unparse(state.keywords[0].value) == ("[BINARY, mixed]" if mode == "argv" else "[BINARY, INPUT_FILE]")
    assert json.loads(files["r5d_angr_concolic_manifest.json"])["mode"] == mode
    assert any(isinstance(n, ast.Constant) and n.value == "/out/answer.json" for n in ast.walk(tree))


@pytest.mark.parametrize("architecture,enum", [("x86","X86"),("amd64","X86_64"),("arm","ARM32"),("aarch64","AARCH64"),("riscv64","RV64")])
def test_triton_ast_preserves_architecture_trace_bindings_and_limits(architecture, enum, monkeypatch):
    plan = inert_call(monkeypatch, engine.build_triton_taint_plan, spec(architecture=architecture), trace_name="offline.json", output_name="taint.json")
    assert plan == engine.build_triton_taint_plan(spec(architecture=architecture), trace_name="offline.json", output_name="taint.json")
    tree = ast.parse(dict(plan.generated_files)["r5d_triton_taint.py"])
    nodes = constants(tree)
    for name, expected in {"TRACE_PATH":"/work/offline.json","OUTPUT_PATH":"/out/taint.json","INPUT_BASE":0x71234000,
                           "MAX_INSTRUCTIONS":73,"TRACE_ARCHITECTURE":architecture,"TAINT_SINKS":(0x601300,),"SYMBOLIC_OFFSETS":(0,2,7)}.items():
        assert_literal(nodes[name], expected)
    architecture_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "ctx.setArchitecture"]
    assert len(architecture_calls) == 1 and ast.unparse(architecture_calls[0].args[0]) == "ARCH." + enum
    assert isinstance(nodes["required"], ast.Set)
    assert all(isinstance(item, ast.Constant) for item in nodes["required"].elts)
    assert {item.value for item in nodes["required"].elts} == {"contract_version","reconciliation","architecture","input_address","initial_registers","initial_memory","instructions"}
    reads = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and ast.unparse(n.func) == "handle.read"]
    assert len(reads) == 1 and ast.unparse(reads[0].args[0]) == "MAX_TRACE_BYTES + 1"
    assert plan.runtime_requirements == ("triton-library",)
    assert json.loads(plan.manifest)["trace_name"] == "offline.json"


def test_matrix_sandbox_contract_and_rendered_manifest(monkeypatch):
    plans = inert_call(monkeypatch, engine.build_analysis_matrix, spec(), engines=["triton", "angr"])
    assert plans == engine.build_analysis_matrix(spec())
    assert [p.engine for p in plans] == ["angr-concolic", "triton-taint"]
    for plan in plans:
        assert (plan.network,plan.read_only_root,plan.drop_capabilities) == ("none",True,("ALL",))
        assert plan.timeout_seconds == 11 and plan.image == "csctf-analysis:1"
        assert plan.image_build_required is True and plan.artifact_execution_expected is True
        assert plan.to_dict()["manifest"] == plan.manifest
    rendered = inert_call(monkeypatch, engine.render_plan_manifest, plans)
    rows = json.loads(rendered)
    assert len(rows) == 2
    for row, which in zip(rows, ["angr", "triton"]):
        assert row["manifest"] == expected_manifest(which)
        assert "generated_files" not in row and row["network"] == "none"
    assert rendered == engine.render_plan_manifest(plans)
    assert len(engine.build_analysis_matrix(spec(taint_sinks=[], input_address=None))) == 1


def clean(function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except Exception as exc:
        assert type(exc) is ValueError, f"leaked {type(exc).__name__}: {exc}"


@pytest.mark.parametrize("field,value", [
    ("input_name","../bad"),("input_name", "x"*129),("input_name", "x\0"),
    ("architecture","sparc"),("mode","socket"),("seed_hex","ffx0"),("seed_hex","f"),
    ("seed_hex",""),("seed_hex","ff"*4097),("symbolic_offsets",[]),("symbolic_offsets",[0,0]),
    ("symbolic_offsets",[True]),("symbolic_offsets",[-1]),("symbolic_offsets",[9]),
    ("find",["__import__('os').system('true')"]),("find",[-1]),("find",[2**64]),("find",[True]),
    ("find",[1]*257),("trace",[1]*8193),("base_address",None),("entrypoint",0x500000),
    ("input_address",2**64-2),("max_steps",0),("max_steps",1000001),("max_steps",True),
    ("max_active",None),("timeout_seconds",1.5),("solution_limit",65),
])
def test_invalid_spec_fields_are_valueerror_only(field, value):
    raw = spec(**{field:value})
    with pytest.raises(ValueError) as info:
        engine.normalize_spec(raw)
    assert type(info.value) is ValueError


def test_random_seed_text_and_hex_mutation_are_bounded():
    rng = random.Random(901)
    for size in [1,2,8,64]:
        raw = rng.randbytes(size)
        parsed = engine.normalize_spec(spec(seed_hex=raw.hex(),symbolic_offsets=[0]))
        assert parsed.seed == raw
    for raw in [spec(),{}, {"seed_hex":"\xff"*100}, {"unexpected":1}]:
        for function in [engine.normalize_spec,engine.build_angr_concolic_plan,engine.build_triton_taint_plan,engine.build_analysis_matrix]:
            clean(function, raw)


@pytest.mark.parametrize("cap", ["MAX_SEED_BYTES","MAX_SYMBOLIC_OFFSETS","MAX_GOALS","MAX_TRACE_ADDRESSES","MAX_STEPS","MAX_ACTIVE","MAX_TIMEOUT"])
def test_explicit_small_input_caps(monkeypatch, cap):
    monkeypatch.setattr(engine, cap, 1)
    with pytest.raises(ValueError):
        engine.normalize_spec(spec())


@pytest.mark.parametrize("builder", [engine.build_angr_concolic_plan,engine.build_triton_taint_plan])
def test_generated_source_cap(monkeypatch,builder):
    monkeypatch.setattr(engine,"MAX_SOURCE_CHARS",64)
    with pytest.raises(ValueError,match="source exceeds"):
        builder(spec())


def test_small_trace_cap_is_embedded_not_executed(monkeypatch):
    monkeypatch.setattr(engine,"MAX_TRACE_BYTES",16)
    plan=engine.build_triton_taint_plan(spec())
    assert_literal(constants(ast.parse(plan.generated_files[0][1]))["MAX_TRACE_BYTES"],16)


@pytest.mark.parametrize("function", [engine.normalize_spec,engine.ConcolicSpec.from_mapping,engine.build_angr_concolic_plan,engine.build_triton_taint_plan,engine.build_analysis_matrix])
def test_nonmapping_spec_fail_closed(function):
    clean(function,None)


@pytest.mark.parametrize("field,value", [("architecture",[]),("mode",{}),("seed_hex",None)])
def test_unhashable_fields_and_surrogate_seed_fail_closed(field,value):
    raw=spec(**{field:value})
    if field=="seed_hex":
        raw["seed"]="\ud800"
    clean(engine.normalize_spec,raw)


@pytest.mark.parametrize("engines", [3,[[]]])
def test_invalid_matrix_engine_container_fail_closed(engines):
    clean(engine.build_analysis_matrix,spec(),engines=engines)


def test_manifest_invalid_engine_fail_closed():
    clean(engine.render_spec_manifest,spec(),[])


@pytest.mark.parametrize("plans", [None,[None]])
def test_render_plan_manifest_invalid_container_fail_closed(plans):
    clean(engine.render_plan_manifest,plans)


def test_render_plan_manifest_invalid_json_fail_closed():
    plan=replace(engine.build_angr_concolic_plan(spec()),manifest="[")
    clean(engine.render_plan_manifest,[plan])


def test_unsupported_triton_mips_declined():
    # Triton's published architecture_e lists ARM32/AARCH64/RV32/RV64/X86/X86_64 only.
    with pytest.raises(ValueError):
        engine.build_triton_taint_plan(spec(architecture="mips"))
