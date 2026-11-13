"""Inert plan validation against caller metadata and documented emulator APIs.

https://www.unicorn-engine.org/docs/tutorial.html
https://docs.qiling.io/en/latest/howto/
Generated Python is parsed as AST only. No firmware or plan is executed.
The module declares no custom exception: exact ValueError is its validation
contract here; TypeError/KeyError/etc. remain isolated strict BUG cases.
"""
import ast
import builtins
import copy
import json
import random
import socket
import subprocess
from pathlib import Path

import pytest
import firmware_emulation_plans as engine


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        if name.split(".")[0] in {"unicorn", "qiling", "angr", "triton"}:
            raise AssertionError("plan builder imported an emulator")
        return original_import(name, *args, **kwargs)
    def blocked(*args, **kwargs):
        raise AssertionError("plan builder tried I/O or execution")
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(Path, "read_bytes", blocked)
    monkeypatch.setattr(Path, "read_text", blocked)
    monkeypatch.setattr(Path, "open", blocked)


def raw_spec(**overrides):
    result = dict(input_name="known.bin", format="raw", architecture="amd64",
        endian="little", operating_system="baremetal", base_address=0x12345000,
        entrypoint=0x12345080, memory_regions=[
            {"address": 0x12345000, "size": 0x2000, "permissions": "xr"}],
        hook_addresses=[0x12345090, 0x12345090], stop_addresses=[0x12345100],
        max_instructions=57, timeout_seconds=3)
    result.update(overrides)
    return result


def elf_spec(**overrides):
    result = dict(input_name="known.elf", format="elf", architecture="arm",
        operating_system="linux", rootfs_name="rootfs", hook_addresses=[0x8048120],
        stop_addresses=[0x8048130], max_instructions=91, timeout_seconds=4)
    result.update(overrides)
    return result


def constants(source):
    """Only literal top-level assignments; this never evals or executes code."""
    tree = ast.parse(source)
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return result


def assert_inert_plan(plan, output):
    assert plan.network == "none" and plan.read_only_root is True
    assert plan.drop_capabilities == ("ALL",)
    assert plan.expected_outputs == (output,)
    assert plan.argv[0] == "python3"
    python_name, source = next((name, text) for name, text in plan.generated_files if name.endswith(".py"))
    assert plan.argv[1] == "/plan/" + python_name
    assert constants(source)["OUTPUT"] == "/out/" + output
    manifest = json.loads(plan.manifest)
    assert manifest["sandbox_required"] is True and manifest["network"] == "none"
    assert plan.to_dict()["engine"] == plan.engine
    rendered = json.loads(engine.render_plan_manifest([plan]))[0]
    assert rendered["manifest"] == manifest
    assert rendered["argv"] == list(plan.argv)
    return source, manifest


@pytest.mark.parametrize("architecture,endian,instruction_set,arch_token,mode", [
    ("x86", "little", "default", "UC_ARCH_X86", "UC_MODE_32"),
    ("amd64", "little", "default", "UC_ARCH_X86", "UC_MODE_64"),
    ("arm", "little", "arm", "UC_ARCH_ARM", "UC_MODE_ARM"),
    ("arm", "big", "arm", "UC_ARCH_ARM", "UC_MODE_BIG_ENDIAN"),
    ("arm", "little", "thumb", "UC_ARCH_ARM", "UC_MODE_THUMB"),
    ("arm", "little", "cortex-m", "UC_ARCH_ARM", "UC_MODE_MCLASS"),
    ("aarch64", "little", "default", "UC_ARCH_ARM64", "UC_MODE_ARM"),
    ("mips", "big", "default", "UC_ARCH_MIPS", "UC_MODE_MIPS32"),
    ("mips64", "little", "default", "UC_ARCH_MIPS", "UC_MODE_MIPS64"),
    ("riscv32", "little", "default", "UC_ARCH_RISCV", "UC_MODE_RISCV32"),
    ("riscv64", "little", "default", "UC_ARCH_RISCV", "UC_MODE_RISCV64"),
])
def test_unicorn_parameters_and_ast(architecture, endian, instruction_set, arch_token, mode):
    spec = raw_spec(architecture=architecture, endian=endian, instruction_set=instruction_set)
    before = copy.deepcopy(spec)
    plan = engine.build_unicorn_plan(spec, output_name="trace.json")
    assert plan == engine.build_unicorn_plan(spec, output_name="trace.json")
    assert spec == before
    source, manifest = assert_inert_plan(plan, "trace.json")
    values = constants(source)
    assert values["BASE"] == 0x12345000 and values["ENTRY"] == 0x12345080
    assert values["START"] == (0x12345081 if instruction_set in {"thumb", "cortex-m"} else 0x12345080)
    assert values["HOOKS"] == (0x12345090,) and values["STOPS"] == (0x12345100,)
    assert values["MAX_INSTRUCTIONS"] == 57 and values["TIMEOUT_US"] == 3000000
    assert values["REGIONS"] == ((0x12345000, 0x2000, "rx"),)
    assert manifest["architecture"] == architecture
    uc = next(node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "Uc")
    assert ast.unparse(uc.args[0]) == arch_token
    mode_expression = ast.unparse(uc.args[1])
    # ARM and LITTLE_ENDIAN both have value zero in Unicorn's public enum.
    if architecture == "aarch64":
        assert mode_expression in {"UC_MODE_ARM", "UC_MODE_LITTLE_ENDIAN", "0"}
    else:
        assert mode in mode_expression
    assert engine.build_emulation_matrix(spec) == (engine.build_unicorn_plan(spec),)


@pytest.mark.parametrize("architecture,bits", [("arm", 32), ("aarch64", 64), ("amd64", 64), ("mips", 32)])
def test_qiling_parameters_and_ast(architecture, bits):
    spec = elf_spec(architecture=architecture)
    plan = engine.build_qiling_plan(spec, output_name="q.json")
    assert plan == engine.build_qiling_plan(spec, output_name="q.json")
    source, manifest = assert_inert_plan(plan, "q.json")
    values = constants(source)
    assert values["BINARY"] == "/work/known.elf" and values["ROOTFS"] == "/work/rootfs"
    assert values["EXPECTED_BITS"] == bits and values["HOOKS"] == (0x8048120,)
    assert manifest["limits"] == {"instructions": 91, "timeout_seconds": 4}
    assert engine.build_emulation_matrix(spec) == (engine.build_qiling_plan(spec),)
    assert engine.render_spec_manifest(spec, "qiling") == plan.manifest


def test_normalization_sorting_and_thumb_address_canonicalization():
    region = engine.MemoryRegion.from_mapping({"address": "0x1000", "size": 4096, "permissions": "xwr"})
    assert (region.address, region.size, region.permissions) == (4096, 4096, "rwx")
    assert engine.MemoryRegion.from_mapping(region) == region
    spec = raw_spec(architecture="arm", instruction_set="thumb", entrypoint=0x12345081,
        hook_addresses=[0x12345093, 0x12345090, 0x12345091], stop_addresses=[0x12345101])
    normalized = engine.normalize_spec(spec)
    assert normalized.entrypoint == 0x12345080
    assert normalized.hook_addresses == (0x12345090, 0x12345092)
    assert normalized.stop_addresses == (0x12345100,)
    assert engine.FirmwareSpec.from_mapping(normalized) == normalized


@pytest.mark.parametrize("field,value", [
    ("input_name", "../outside"), ("input_name", "x';__import__('os')"),
    ("base_address", "0xg"), ("entrypoint", -1), ("entrypoint", 0x12350000),
    ("max_instructions", 0), ("max_instructions", 10000001), ("timeout_seconds", 1801),
    ("memory_regions", []), ("hook_addresses", [0] * 257), ("hook_addresses", [2**64]),
    ("memory_regions", [{"address": 0x12345001, "size": 4096}]),
    ("memory_regions", [{"address": 0x12345000, "size": 4096, "permissions": "rr"}]),
])
def test_invalid_schema_exact_validation_error(field, value):
    with pytest.raises(ValueError) as caught:
        engine.normalize_spec(raw_spec(**{field: value}))
    assert type(caught.value) is ValueError


def test_seeded_spec_mutations_fail_closed():
    rng = random.Random(901)
    corpus = [{}, {"format": "raw"}, raw_spec(input_name="\xff" * 129)]
    corpus.extend(raw_spec(input_name="".join(chr(rng.randrange(32, 128)) for _ in range(30))) for _ in range(30))
    corpus.extend(raw_spec(entrypoint=0x12345080 ^ (1 << bit)) for bit in range(64))
    for spec in corpus:
        for function in (engine.normalize_spec, engine.build_unicorn_plan, engine.build_emulation_matrix):
            try:
                function(spec)
            except ValueError as error:
                assert type(error) is ValueError


def test_small_source_and_memory_bounds(monkeypatch):
    monkeypatch.setattr(engine, "MAX_TOTAL_MEMORY", 4096)
    with pytest.raises(ValueError):
        engine.normalize_spec(raw_spec())
    monkeypatch.setattr(engine, "MAX_TOTAL_MEMORY", 512 << 20)
    monkeypatch.setattr(engine, "MAX_SOURCE_CHARS", 20)
    for function, spec in [(engine.build_unicorn_plan, raw_spec()), (engine.build_qiling_plan, elf_spec())]:
        with pytest.raises(ValueError, match="source exceeds"):
            function(spec)


@pytest.mark.parametrize("function,argument", [
    (engine.normalize_spec, None), (engine.MemoryRegion.from_mapping, None),
    (engine.normalize_spec, raw_spec(architecture=[])),
    (engine.normalize_spec, raw_spec(format=[])),
    (engine.normalize_spec, raw_spec(endian=[])),
    (engine.normalize_spec, raw_spec(operating_system=[])),
    (engine.render_plan_manifest, [None]), (engine.render_plan_manifest, None),
])
def test_bad_type_validation_contract(function, argument):
    try:
        function(argument)
    except ValueError as error:
        assert type(error) is ValueError


def test_32bit_entry_address_is_representable():
    spec = raw_spec(architecture="x86", base_address=0x100000000, entrypoint=0x100000080,
        memory_regions=[{"address": 0x100000000, "size": 4096}], hook_addresses=[], stop_addresses=[])
    with pytest.raises(ValueError):
        engine.build_unicorn_plan(spec)
