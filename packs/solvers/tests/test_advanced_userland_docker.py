"""Coverage manifest and opt-in offline Docker round trips for advanced userland deltas."""
from pathlib import Path
import inspect
import json
import os
import shutil
import struct
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import dl_runtime as dl  # noqa: E402
import multiarch_srop as srop  # noqa: E402
import one_gadget as one  # noqa: E402
import stack_migration as migration  # noqa: E402
from gadget_catalog import Gadget, GadgetCatalog  # noqa: E402


def _catalog():
    return GadgetCatalog(
        "amd64", 64, "little", 2, 0x401000,
        (
            Gadget(0x401010, 0x10, "pop rdi ; ret", b"\x5f\xc3", 16),
            Gadget(0x401020, 0x20, "pop rsi ; ret", b"\x5e\xc3", 16),
            Gadget(0x401030, 0x30, "pop rdx ; ret", b"\x5a\xc3", 16),
            Gadget(0x401040, 0x40, "pop rsp ; ret", b"\x5c\xc3", 16),
            Gadget(0x401050, 0x50, "leave ; ret", b"\xc9\xc3", 16),
        ),
    )


def _libc_fixture():
    build_id = bytes.fromhex("00112233445566778899aabbccddeeff01020304")
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    code_offset = 176
    code = b"\x90" * 0x100
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\x00" + build_id
    note_offset = code_offset + len(code)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0x1000, 64, 0, 0, 64, 56, 2, 0, 0, 0
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, code_offset, 0x1000, 0x1000,
                       len(code), len(code), 0x1000)
    notes = struct.pack("<IIQQQQQQ", 4, 4, note_offset, 0, 0,
                        len(note), len(note), 4)
    return header + load + notes + code + note


def _samples():
    catalog = _catalog()
    pivot_catalog = migration.catalog_pivots(catalog)
    layout = dl.LinkMapLayout(0x300, 0, 8, 16, 24, 32, 0x40, 8, 32)
    modules = (srop, migration, one, dl)
    samples = {
        "multiarch_srop.build_sigreturn_frame": (
            srop.build_sigreturn_frame("aarch64", {"x8": 221, "sp": 0x800000, "pc": 0x401000}),
            "frame.pc",
        ),
        "multiarch_srop.build_srop_trigger": (
            srop.build_srop_trigger(
                "aarch64", {"sp": 0x800000, "pc": 0x401000},
                setup_words=(0x401100, 139), sigreturn_number_index=1,
                syscall_gadget=0x401000, overflow_offset=8,
            ),
            "sigreturn_frame",
        ),
        "multiarch_srop.build_srop_execve": (
            srop.build_srop_execve(
                "riscv64", command_address=0x601000, stack_address=0x800000,
                syscall_gadget=0x401000, setup_words=(0x401100, 139),
                sigreturn_number_index=1, overflow_offset=8,
            ),
            "frame.a7",
        ),
        "stack_migration.build_pivot_stage": (
            migration.build_pivot_stage(
                pivot_catalog.choose(), new_stack_address=0x404800
            ),
            "new_stack_address",
        ),
        "stack_migration.build_catalog_pivot_stage": (
            migration.build_catalog_pivot_stage(catalog, new_stack_address=0x404800),
            "pivot_gadget",
        ),
        "stack_migration.build_read_then_migrate_amd64": (
            migration.build_read_then_migrate_amd64(
                catalog, read_address=0x401080, destination=0x404800,
                stage2=b"R5B_STAGE2", overflow_offset=8,
            ),
            "stage2",
        ),
        "stack_migration.build_leave_hop_bundle": (
            migration.build_leave_hop_bundle(
                (migration.LeaveHop(0x404800, 0x404900, 0x401050),)
            ),
            "hop[0]",
        ),
        "one_gadget.build_one_gadget_plan": (
            one.build_one_gadget_plan(
                _libc_fixture(), libc_base=0x7FFFF7DC0000, gadget_offset=0x1010,
                constraints=("rax == NULL",), register_state={"rax": 1},
                stack_pointer=0x7000, controllable_registers={"rax"},
                register_loaders={"rax": 0x401100},
                payload_address=0x6FE8,
            ),
            "one_gadget",
        ),
        "dl_runtime.build_dynamic_vector": (
            dl.build_dynamic_vector(((dl.DT_STRTAB, 0x500100),)), "dyn[0]",
        ),
        "dl_runtime.build_relocation_table": (
            dl.build_relocation_table((dl.RelocationSpec(0x601000, 1, 7),)), "rel[0]",
        ),
        "dl_runtime.build_relr_table": (
            dl.build_relr_table((0x600000, 0x600008)), "relr[0]",
        ),
        "dl_runtime.build_link_map_image": (
            dl.build_link_map_image(
                layout, base_address=0x500000, l_addr=0,
                l_name=0x500400, l_ld=0x500300,
            ),
            "l_addr",
        ),
        "dl_runtime.build_dl_runtime_resolve_stack": (
            dl.build_dl_runtime_resolve_stack(
                architecture="amd64", resolver_entry=0x7FFFF7FE0000,
                link_map=0x500000, relocation_selector=0, return_address=0x401000,
            ),
            "resolver_entry",
        ),
        "dl_runtime.build_dl_fixup_bundle": (
            dl.build_dl_fixup_bundle(
                layout, architecture="amd64", image_address=0x500000,
                l_addr=0, symbol_name=b"system", relocation_target=0x601000,
                relocation_type=7, glibc_version="2.39",
            ),
            "symbol_name",
        ),
    }
    return modules, samples


def _public_builders(modules):
    return {
        f"{module.__name__}.{name}"
        for module in modules
        for name, value in inspect.getmembers(module, inspect.isfunction)
        if name.startswith("build_") and value.__module__ == module.__name__
    }


def _records():
    modules, samples = _samples()
    assert set(samples) == _public_builders(modules)
    records = []
    for name, (build, label) in sorted(samples.items()):
        offset, width = build.placements[label], build.widths[label]
        records.append({
            "name": name,
            "payload": build.payload.hex(),
            "offset": offset,
            "expected": build.payload[offset:offset + width].hex(),
        })
    return records


def test_advanced_docker_manifest_covers_every_new_public_builder():
    records = _records()
    assert len(records) == 14
    for row in records:
        payload = bytes.fromhex(row["payload"])
        expected = bytes.fromhex(row["expected"])
        assert payload[row["offset"]:row["offset"] + len(expected)] == expected


@pytest.mark.skipif(
    os.environ.get("R5B_DOCKER_VERIFY") != "1",
    reason="set R5B_DOCKER_VERIFY=1 for --pull=never --network none verification",
)
def test_advanced_builders_round_trip_in_read_only_networkless_container():
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker CLI unavailable")
    image = "csctf-sandbox:2"
    inspect_image = subprocess.run(
        [docker, "image", "inspect", image], capture_output=True, text=True, check=False
    )
    if inspect_image.returncode:
        pytest.skip(f"prebuilt image unavailable: {image}")
    verifier = (
        "import json,sys\n"
        "rows=json.load(sys.stdin)\n"
        "for row in rows:\n"
        " raw=bytes.fromhex(row['payload']); exp=bytes.fromhex(row['expected']); off=row['offset']\n"
        " assert raw[off:off+len(exp)] == exp, row['name']\n"
        "print('R5B_ADVANCED_OK:%d' % len(rows))\n"
    )
    command = [
        docker, "run", "--rm", "-i", "--pull=never", "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "64", "--memory", "256m",
        image, "python3", "-c", verifier,
    ]
    records = _records()
    completed = subprocess.run(
        command, input=json.dumps(records, sort_keys=True), capture_output=True,
        text=True, timeout=120, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"R5B_ADVANCED_OK:{len(records)}"

