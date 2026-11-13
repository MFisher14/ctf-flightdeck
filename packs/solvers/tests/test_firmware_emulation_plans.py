"""Tests for source-only Qiling and Unicorn firmware plans."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import firmware_emulation_plans as plans  # noqa: E402


def _raw(**updates):
    value = {
        "input_name": "flash.bin",
        "format": "raw",
        "architecture": "arm",
        "endian": "little",
        "instruction_set": "arm",
        "operating_system": "baremetal",
        "base_address": "0x10000",
        "entrypoint": "0x10100",
        "memory_regions": [
            {"address": "0x10000", "size": 0x4000, "permissions": "rx"},
            {"address": "0x20000", "size": 0x2000, "permissions": "rw"},
        ],
        "hook_addresses": [0x10100, 0x10200],
        "stop_addresses": [0x10300],
        "max_instructions": 12345,
        "timeout_seconds": 20,
    }
    value.update(updates)
    return value


def _elf(**updates):
    value = {
        "input_name": "daemon.elf",
        "format": "elf",
        "architecture": "mips",
        "endian": "big",
        "operating_system": "linux",
        "rootfs_name": "rootfs",
        "hook_addresses": [0x400800],
        "stop_addresses": [0x400900],
        "max_instructions": 4000,
        "timeout_seconds": 25,
    }
    value.update(updates)
    return value


def test_raw_matrix_builds_only_unicorn_and_is_deterministic():
    first = plans.build_emulation_matrix(_raw())
    second = plans.build_emulation_matrix(_raw(), engines=("unicorn",))
    assert first == second
    assert [item.engine for item in first] == ["unicorn"]
    plan = first[0]
    assert plan.network == "none"
    assert plan.read_only_root is True
    assert plan.drop_capabilities == ("ALL",)
    assert plan.artifact_execution_expected is True
    assert plan.timeout_seconds == 20
    assert plan.image == "csctf-pwn:1"
    assert plan.image_build_required is False
    assert plan.runtime_requirements == ("unicorn",)
    assert any("MMIO" in note for note in plan.review_notes)
    rendered = json.loads(plans.render_plan_manifest(first))
    assert rendered[0]["manifest"]["sandbox_required"] is True


def test_unicorn_source_maps_explicit_regions_and_caps_execution():
    plan = plans.build_unicorn_plan(_raw(), output_name="trace.json")
    source = plan.generated_files[0][1]
    compile(source, "<r5d-unicorn-firmware>", "exec")
    assert "from unicorn.arm_const import UC_ARM_REG_PC" in source
    assert "Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)" in source
    assert "REGIONS = ((65536, 16384, 'rx'), (131072, 8192, 'rw'))" in source
    assert "handle.read(268435457)" in source
    assert "count=MAX_INSTRUCTIONS" in source
    assert "timeout=TIMEOUT_US" in source
    assert "networkless CSCTF Docker sandbox" in source
    assert plan.expected_outputs == ("trace.json",)


@pytest.mark.parametrize(
    "arch,endian,needle",
    [
        ("aarch64", "big", "UC_ARCH_ARM64, UC_MODE_BIG_ENDIAN"),
        ("mips", "little", "UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN"),
        ("mips64", "big", "UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN"),
        ("riscv32", "little", "UC_ARCH_RISCV, UC_MODE_RISCV32"),
        ("riscv64", "little", "UC_ARCH_RISCV, UC_MODE_RISCV64"),
    ],
)
def test_unicorn_architecture_endian_matrix(arch, endian, needle):
    source = plans.build_unicorn_plan(
        _raw(architecture=arch, endian=endian, instruction_set="default")
    ).generated_files[0][1]
    compile(source, f"<r5d-{arch}>", "exec")
    assert needle in source


def test_qiling_plan_is_source_only_bounded_and_reviewable():
    plan = plans.build_qiling_plan(_elf())
    source = plan.generated_files[0][1]
    compile(source, "<r5d-qiling-firmware>", "exec")
    assert "BINARY = '/work/daemon.elf'" in source
    assert "ROOTFS = '/work/rootfs'" in source
    assert "Qiling([BINARY], ROOTFS" in source
    assert "Path(BINARY).stat().st_size" in source
    assert "firmware image is empty or exceeds" in source
    assert "detected_arch not in EXPECTED_ARCH_NAMES" in source
    assert "detected_bits != EXPECTED_BITS" in source
    assert "loader architecture/width disagrees" in source
    assert "loader endian disagrees" in source
    assert "loader OS disagrees" in source
    assert "multithread=False" in source
    assert "count >= MAX_INSTRUCTIONS" in source
    assert "ql.emu_stop()" in source
    assert any("MIPS" in note for note in plan.review_notes)
    assert plan.image == "csctf-analysis:1"
    assert plan.image_build_required is True
    assert plan.runtime_requirements == ("qiling",)
    assert plans.build_emulation_matrix(_elf())[0] == plan


@pytest.mark.parametrize(
    "update,match",
    [
        ({"input_name": "../flash"}, "unsafe"),
        ({"format": "uimage"}, "format"),
        ({"architecture": "sparc"}, "architecture"),
        ({"endian": "middle"}, "endian"),
        ({"architecture": "x86", "endian": "big"}, "little"),
        ({"instruction_set": None}, "instruction_set"),
        ({"memory_regions": []}, "requires"),
        ({"entrypoint": 0xFFFF}, "precede"),
        ({"base_address": 0x50000, "entrypoint": 0x50100}, "outside"),
        ({"memory_regions": [{"address": 0x10001, "size": 0x1000}]}, "aligned"),
        ({"memory_regions": [{"address": 0x10000, "size": 0x1001}]}, "aligned"),
        ({"memory_regions": [{"address": 0x10000, "size": 0x1000, "permissions": "rr"}]}, "permissions"),
        ({"memory_regions": [
            {"address": 0x10000, "size": 0x3000},
            {"address": 0x11000, "size": 0x1000},
        ]}, "overlap"),
        ({"memory_regions": [
            {"address": 0x10000, "size": 0x10000000},
            {"address": 0x20000000, "size": 0x10000000},
            {"address": 0x40000000, "size": 0x1000},
        ]}, "aggregate"),
        ({"memory_regions": [
            {"address": 0x10000, "size": 0x4000, "permissions": "rw"},
            {"address": 0x20000, "size": 0x2000, "permissions": "rw"},
        ]}, "executable"),
        ({"hook_addresses": [0x900000]}, "hook/stop"),
        ({"entrypoint": 0x20100}, "share"),
        ({"max_instructions": 0}, "max_instructions"),
    ],
)
def test_raw_profile_rejects_unsafe_ambiguous_or_unbounded_values(update, match):
    with pytest.raises(ValueError, match=match):
        plans.FirmwareSpec.from_mapping(_raw(**update))


def test_elf_and_engine_compatibility_are_explicit():
    with pytest.raises(ValueError, match="rootfs"):
        plans.FirmwareSpec.from_mapping(_elf(rootfs_name=None))
    with pytest.raises(ValueError, match="derives"):
        plans.FirmwareSpec.from_mapping(_elf(base_address=0x400000))
    with pytest.raises(ValueError, match="derives"):
        plans.FirmwareSpec.from_mapping(_elf(entrypoint=0x400000))
    with pytest.raises(ValueError, match="derives"):
        plans.FirmwareSpec.from_mapping(_elf(memory_regions=[{"address": 0x1000, "size": 0x1000}]))
    with pytest.raises(ValueError, match="operating_system"):
        plans.FirmwareSpec.from_mapping(_elf(operating_system="unknown"))
    with pytest.raises(ValueError, match="Qiling"):
        plans.build_qiling_plan(_raw())
    with pytest.raises(ValueError, match="Unicorn"):
        plans.build_unicorn_plan(_elf())
    with pytest.raises(ValueError, match="compatible"):
        plans.build_emulation_matrix(_raw(), engines=("qiling",))
    with pytest.raises(ValueError, match="distinct"):
        plans.build_emulation_matrix(_raw(), engines=("unicorn", "unicorn"))


def test_manifest_order_is_stable_and_unknown_keys_are_rejected():
    first = plans.render_spec_manifest(_raw(), "unicorn")
    second = plans.render_spec_manifest({
        "memory_regions": _raw()["memory_regions"],
        "entrypoint": "0x10100",
        "base_address": "0x10000",
        "operating_system": "baremetal",
        "endian": "little",
        "instruction_set": "arm",
        "architecture": "arm",
        "format": "raw",
        "input_name": "flash.bin",
        "hook_addresses": [0x10200, 0x10100],
        "stop_addresses": [0x10300],
        "max_instructions": 12345,
        "timeout_seconds": 20,
    }, "unicorn")
    assert first == second
    parsed = json.loads(first)
    assert parsed["memory_regions"][0] == {
        "address": 65536, "permissions": "rx", "size": 16384
    }
    with pytest.raises(ValueError, match="unknown"):
        plans.FirmwareSpec.from_mapping({**_raw(), "typo": 1})
    with pytest.raises(ValueError, match="engine"):
        plans.render_spec_manifest(_raw(), "angr")


def test_direct_dataclass_instances_are_revalidated():
    invalid = plans.FirmwareSpec(
        input_name="flash.bin", format="raw", architecture="arm", endian="little",
        instruction_set="arm", operating_system="baremetal", rootfs_name=None, base_address=0x10000,
        entrypoint=0x10100, memory_regions=(plans.MemoryRegion(0x10001, 0x1000),),
    )
    with pytest.raises(ValueError, match="aligned"):
        plans.normalize_spec(invalid)


@pytest.mark.parametrize(
    "instruction_set,entrypoint,mode",
    [
        ("thumb", 0x10101, "UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN"),
        ("cortex-m", 0x10101, "UC_MODE_THUMB | UC_MODE_MCLASS | UC_MODE_LITTLE_ENDIAN"),
    ],
)
def test_arm_thumb_and_cortex_m_are_explicit_and_normalize_entry(instruction_set, entrypoint, mode):
    value = plans.FirmwareSpec.from_mapping(_raw(
        instruction_set=instruction_set, entrypoint=entrypoint,
        hook_addresses=[0x10101], stop_addresses=[0x10301],
    ))
    assert value.entrypoint == 0x10100
    assert value.hook_addresses == (0x10100,)
    assert value.stop_addresses == (0x10300,)
    source = plans.build_unicorn_plan(value).generated_files[0][1]
    assert f"Uc(UC_ARCH_ARM, {mode})" in source
    assert "START = 65793" in source
    assert "if not BASE <= ENTRY < BASE + len(image)" in source
    assert "uc.emu_start(START, END" in source
    assert any("canonical even" in note for note in plans.build_unicorn_plan(value).review_notes)


def test_module_ast_cannot_import_emulators_spawn_or_open_artifacts():
    source = (REPO / "solvers" / "binary" / "firmware_emulation_plans.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported & {
        "qiling", "unicorn", "subprocess", "socket", "requests", "httpx", "os"
    }
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"exec", "eval", "compile", "open", "__import__"}

