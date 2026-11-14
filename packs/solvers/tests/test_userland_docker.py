"""Opt-in, networkless Docker round trips for every r5b userland payload builder.

Set ``CTF_R5B_DOCKER_VERIFY=1`` (legacy ``R5B_DOCKER_VERIFY=1`` is also
accepted) after the prebuilt ``csctf-pwn:1`` image exists.  The fixed command
uses ``--pull=never --network none``, a read-only root, dropped capabilities,
and resource bounds.  It executes only a trusted byte-slice verifier, never a
challenge artifact or a live exploit.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import format_string_builder as fmt  # noqa: E402
import userland_chains as chains  # noqa: E402
from gadget_catalog import Gadget, GadgetCatalog  # noqa: E402


DOCKER_IMAGE = "csctf-pwn:1"
DOCKER_VERIFY = (
    os.environ.get("CTF_R5B_DOCKER_VERIFY") == "1"
    or os.environ.get("R5B_DOCKER_VERIFY") == "1"
)


def _records():
    catalog = GadgetCatalog(
        "amd64", 64, "little", 2, 0x401000,
        (
            Gadget(0x401001, 1, "ret", b"\xc3", 8),
            Gadget(0x401010, 0x10, "pop rax ; ret", b"\x58\xc3", 16),
            Gadget(0x401020, 0x20, "pop rdi ; ret", b"\x5f\xc3", 16),
            Gadget(0x401030, 0x30, "syscall ; ret", b"\x0f\x05\xc3", 8),
            Gadget(0x401034, 0x34, "jmp rax", b"\xff\xe0", 0),
            Gadget(0x401036, 0x36, "call rbx", b"\xff\xd3", 8),
            Gadget(0x401040, 0x40, "csu pop rbx rbp r12 r13 r14 r15 ; ret",
                   bytes.fromhex("5b5d415c415d415e415fc3"), 56),
            Gadget(0x401050, 0x50, "csu call [r12+rbx*8] (r13d,r14,r15)",
                   bytes.fromhex("4c89fa4c89f64489ef41ff14dc"), 0),
        ),
    )
    builds = {
        "ret2win": chains.build_ret2win(
            win_address=0x401176, overflow_offset=16
        ),
        "rop_calls": chains.build_rop_calls(
            (chains.CallSpec(0x401030, (1,), "one"),),
            overflow_offset=8, pop_gadgets={"rdi": 0x401200}, final_return=0x401000,
        ),
        "rop_call": chains.build_rop_call(
            function=0x401030, arguments=(1,), overflow_offset=8,
            pop_gadgets={"rdi": 0x401200}, return_address=0x401000,
        ),
        "rop_call_catalog": chains.build_rop_call_from_catalog(
            catalog, function=0x401030, arguments=(1,), overflow_offset=8,
            return_address=0x401000,
        ),
        "ret2libc": chains.build_ret2libc(
            system_address=0x7FFFF7E12340, command_address=0x7FFFF7F65031,
            overflow_offset=8, glibc_version="2.39", pop_rdi=0x401200,
        ),
        "ret2libc_catalog": chains.build_ret2libc_from_catalog(
            catalog, system_address=0x7FFFF7E12340,
            command_address=0x7FFFF7F65031, overflow_offset=8,
            glibc_version="2.39",
        ),
        "syscall": chains.build_syscall_rop(
            syscall_number=60, registers={"rdi": 0},
            pop_gadgets={"rax": 0x401200, "rdi": 0x401202},
            syscall_gadget=0x401204, overflow_offset=8,
        ),
        "syscall_catalog": chains.build_syscall_rop_from_catalog(
            catalog, syscall_number=60, registers={"rdi": 0}, overflow_offset=8,
        ),
        "ret2csu": chains.build_ret2csu(
            csu_pop=0x4012BA, csu_call=0x4012A0, function_table=0x404018,
            arg1=1, arg2=2, arg3=3, overflow_offset=8, return_address=0x401000,
        ),
        "ret2csu_catalog": chains.build_ret2csu_from_catalog(
            catalog, function_table=0x404018, arg1=1, arg2=2, arg3=3,
            overflow_offset=8, return_address=0x401000,
        ),
        "pivot": chains.build_stack_pivot(
            pivot_address=0x404800, pivot_gadget=0x401300,
            overflow_offset=8, strategy="pop-sp",
        ),
        "jop": chains.build_jop_dispatch(
            dispatcher_gadget=0x401500, functional_gadgets=(0x401510,),
            table_address=0x600020, payload_address=0x600000,
            overflow_offset=8, pop_dispatch_register=0x401505,
        ),
        "jop_catalog": chains.build_jop_dispatch_from_catalog(
            catalog, dispatcher_semantic="jmp rax",
            functional_semantics=("call rbx",), table_address=0x600020,
            payload_address=0x600000, overflow_offset=8,
        ),
        "sigframe": chains.build_sigreturn_frame(
            {"rax": 59, "rip": 0x401050}
        ),
        "srop": chains.build_srop(
            frame_registers={"rax": 60, "rdi": 0, "rip": 0x401050},
            syscall_gadget=0x401050, pop_accumulator=0x401052,
            overflow_offset=8,
        ),
        "srop_execve": chains.build_srop_execve(
            syscall_gadget=0x401050, pop_accumulator=0x401052,
            command_address=0x404800, stack_address=0x404900,
            overflow_offset=8,
        ),
        "dlresolve": chains.build_ret2dlresolve(
            plt0=0x401020, rel_plt=0x400500, dynsym=0x400300,
            dynstr=0x400400, relocation_target=0x404018, pop_rdi=0x4012A3,
            payload_address=0x404800, overflow_offset=8,
            glibc_version="2.39",
        ),
        "dlresolve_catalog": chains.build_ret2dlresolve_from_catalog(
            catalog, plt0=0x401020, rel_plt=0x400500, dynsym=0x400300,
            dynstr=0x400400, relocation_target=0x404018,
            payload_address=0x404800, overflow_offset=8,
            glibc_version="2.39",
        ),
        "offset_probe": fmt.build_offset_probe(start=1, stop=4),
        "positional_leak": fmt.build_positional_leak(argument_index=7),
        "fmt_writes": fmt.build_fmt_writes(
            {0x404018: 0x11223344}, first_address_arg=8,
            value_width=4, atom_size=1,
        ),
        "fmt_got": fmt.build_fmt_got_overwrite(
            got_address=0x404018, replacement_address=0x7FFFF7E12340,
            first_address_arg=8, atom_size=2, partial_width=6,
        ),
    }
    preferred = {
        "ret2win": "win_address",
        "rop_calls": "call[0].function_one",
        "rop_call": "call[0].function_target",
        "rop_call_catalog": "call[0].function_target",
        "ret2libc": "call[0].function_system",
        "ret2libc_catalog": "call[0].function_system",
        "syscall": "syscall_gadget",
        "syscall_catalog": "syscall_gadget",
        "ret2csu": "csu_call",
        "ret2csu_catalog": "csu_call",
        "pivot": "pivot_address",
        "jop": "table[0]",
        "jop_catalog": "table[0]",
        "sigframe": "frame.rax",
        "srop": "sigreturn_frame",
        "srop_execve": "frame.rip",
        "dlresolve": "symbol_string",
        "dlresolve_catalog": "symbol_string",
        "offset_probe": "marker",
        "positional_leak": "directive",
        "fmt_writes": "write[0].address",
        "fmt_got": "write[0].address",
    }
    records = []
    for name, build in builds.items():
        label = preferred[name]
        offset = build.placements[label]
        width = build.widths[label]
        records.append({
            "name": name,
            "payload": build.payload.hex(),
            "offset": offset,
            "expected": build.payload[offset:offset + width].hex(),
        })
    return records


def test_docker_roundtrip_manifest_covers_every_public_payload_builder():
    """The opt-in test cannot silently lose a builder when Docker is absent."""

    records = _records()
    assert {row["name"] for row in records} == {
        "ret2win", "rop_calls", "rop_call", "rop_call_catalog", "ret2libc",
        "ret2libc_catalog",
        "syscall", "syscall_catalog", "ret2csu", "ret2csu_catalog",
        "pivot", "jop", "jop_catalog", "sigframe", "srop", "srop_execve",
        "dlresolve", "dlresolve_catalog",
        "offset_probe", "positional_leak", "fmt_writes", "fmt_got",
    }
    for row in records:
        raw = bytes.fromhex(row["payload"])
        expected = bytes.fromhex(row["expected"])
        assert raw[row["offset"]:row["offset"] + len(expected)] == expected


@pytest.mark.skipif(
    not DOCKER_VERIFY,
    reason="set CTF_R5B_DOCKER_VERIFY=1 for isolated payload round trips",
)
def test_all_userland_builders_round_trip_in_offline_amd64_container():
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("docker CLI unavailable")
    inspect = subprocess.run(
        [docker, "image", "inspect", DOCKER_IMAGE],
        capture_output=True, text=True, check=False,
    )
    if inspect.returncode:
        pytest.skip(f"prebuilt image unavailable: {DOCKER_IMAGE}")
    verifier = (
        "import json,sys\n"
        "rows=json.load(sys.stdin)\n"
        "for row in rows:\n"
        " raw=bytes.fromhex(row['payload']); off=row['offset']; exp=bytes.fromhex(row['expected'])\n"
        " assert raw[off:off+len(exp)] == exp, row['name']\n"
        "print('R5B_OK:%d' % len(rows))\n"
    )
    command = [
        docker, "run", "--rm", "-i", "--pull=never", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", DOCKER_IMAGE, "python3", "-I", "-B", "-c", verifier,
    ]
    completed = subprocess.run(
        command,
        input=json.dumps(_records(), sort_keys=True),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"R5B_OK:{len(_records())}"

