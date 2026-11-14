"""Opt-in Docker round trips for every r5b kernel/Windows builder.

Run with::

    CTF_DOCKER_VERIFY=1 .venv/bin/python -m pytest \
        tests/test_r5b_kernel_windows_docker.py -q

The verifier uses only the already-local ``csctf-pwn:1`` image, always with
``--pull=never`` and ``--network none``.  Kernel structures are inertly decoded
and hashed because a userspace container cannot safely emulate a target kernel.
The x86 and x64 Windows egghunter instruction streams are executed in Unicorn;
their harmless stages write fixed markers into emulator memory and stop.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import kernel_pwn as kernel  # noqa: E402
import windows_pwn as windows  # noqa: E402


DOCKER_VERIFY = os.environ.get("CTF_DOCKER_VERIFY") == "1"
DOCKER_SKIP = pytest.mark.skipif(
    not DOCKER_VERIFY,
    reason="set CTF_DOCKER_VERIFY=1 for bounded networkless Docker verification",
)
_SEQUENCE = itertools.count()
KBASE = 0xFFFFFFFF81000000


def _artifact(name, result, marker: bytes | None = None) -> dict[str, object]:
    return {
        "name": name,
        "payload": base64.b64encode(result.payload).decode("ascii"),
        "sha256": hashlib.sha256(result.payload).hexdigest(),
        "placements": dict(result.placements),
        "marker": base64.b64encode(marker).decode("ascii") if marker is not None else None,
    }


def _all_artifacts() -> tuple[list[dict[str, object]], object, object]:
    marker = b"R5B_DOCKER_ROUNDTRIP"
    artifacts = []
    artifacts.append(_artifact("kaslr", kernel.build_kaslr_rebase(
        leaked_address=KBASE + 0x123450, leaked_symbol_offset=0x123450,
        symbol_offsets={"commit_creds": 0x90000}), None))
    artifacts.append(_artifact("pt_regs", kernel.build_pt_regs_frame(
        {"rip": 0x401000, "rsp": 0x7FFFFFFF0000}, prefix=marker), marker))
    artifacts.append(_artifact("ret2usr", kernel.build_ret2usr(
        padding=marker, pop_rdi_ret=KBASE + 0x10, init_cred=KBASE + 0x20,
        commit_creds=KBASE + 0x30, trampoline=KBASE + 0x40,
        user_rip=0x401000, user_cs=0x33, user_rflags=0x202,
        user_rsp=0x7FFFFFFF0000, user_ss=0x2B), marker))
    artifacts.append(_artifact("modprobe", kernel.build_modprobe_path_overwrite(
        modprobe_path_address=0xFFFFFFFF8245A5A0,
        replacement_path="/tmp/R5B_DOCKER_ROUNDTRIP",
        pop_address_ret=KBASE + 0x10, pop_value_ret=KBASE + 0x20,
        write_qword_gadget=KBASE + 0x30, padding=marker), marker))
    artifacts.append(_artifact("cred", kernel.build_cred_overwrite(
        cred_address=0xFFFF888012340000,
        pop_address_ret=KBASE + 0x10, pop_value_ret=KBASE + 0x20,
        write_dword_gadget=KBASE + 0x30, write_qword_gadget=KBASE + 0x40,
        padding=marker), marker))
    artifacts.append(_artifact("pipe_buffer", kernel.build_pipe_buffer(
        page=0xFFFFEA0001234000, offset=1, length=2,
        ops=KBASE + 0x100, flags=kernel.PIPE_BUF_FLAG_CAN_MERGE,
        prefix=marker), marker))
    artifacts.append(_artifact("pipe_page", kernel.build_pipe_page_cache_primitive(
        page=0xFFFFEA0001234000, pipe_buf_ops=KBASE + 0x100,
        file_offset=0x2001, replacement=marker), marker))
    artifacts.append(_artifact("seh", windows.build_seh_overwrite(
        offset_to_nseh=32, seh_handler=0x625011AF, stage=marker), marker))
    artifacts.append(_artifact("seh_records", windows.build_seh_record_chain(
        record_addresses=[0x1000, 0x1008], handler_addresses=[0x401000, 0x402000]), None))

    tag32 = b"r5b!"
    marker32 = b"R5BX860!"
    out32 = 0x300000
    stage32 = (
        b"\xb8" + marker32[:4] + b"\xa3" + struct.pack("<I", out32)
        + b"\xb8" + marker32[4:] + b"\xa3" + struct.pack("<I", out32 + 4) + b"\xcc"
    )
    egg32 = windows.build_egghunter(
        architecture="x86", tag=tag32, stage=stage32,
    )
    # The x86 stage loads the two marker dwords separately; the egg itself is
    # the contiguous structural marker.  Unicorn below verifies the full stage
    # marker after execution.
    artifacts.append(_artifact("egghunter_x86", egg32, tag32))

    tag64 = b"R5B!"
    marker64 = b"R5BX640!"
    out64 = 0x300000
    stage64 = (
        b"\x48\xb8" + marker64 + b"\x48\xa3" + struct.pack("<Q", out64) + b"\xcc"
    )
    egg64 = windows.build_egghunter(
        architecture="x64", tag=tag64, stage=stage64,
        range_start=0x200000, range_end=0x201000,
    )
    artifacts.append(_artifact("egghunter_x64", egg64, marker64))
    return artifacts, egg32, egg64


def _docker(command: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    name = f"csctf-r5b-kernel-windows-{os.getpid()}-{next(_SEQUENCE)}"
    argv = [
        "docker", "run", "--pull", "never", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--name", name, "--stop-timeout", "1",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "64", "--memory", "256m", "csctf-pwn:1", *command,
    ]
    try:
        return subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(
            ["docker", "stop", "--time", "1", name], check=False,
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(
            ["docker", "rm", "--force", name], check=False,
            capture_output=True, text=True, timeout=5,
        )
        raise


@DOCKER_SKIP
def test_every_builder_round_trips_and_egghunters_reach_markers_in_unicorn():
    artifacts, egg32, egg64 = _all_artifacts()
    document = {
        "artifacts": artifacts,
        "x86": {
            "hunter": base64.b64encode(egg32.slice("hunter")).decode(),
            "egg_stage": base64.b64encode(egg32.payload[egg32.placements["egg.first"]:]).decode(),
            "marker": base64.b64encode(b"R5BX860!").decode(),
        },
        "x64": {
            "hunter": base64.b64encode(egg64.slice("hunter")).decode(),
            "egg_stage": base64.b64encode(egg64.payload[egg64.placements["egg.first"]:]).decode(),
            "marker": base64.b64encode(b"R5BX640!").decode(),
        },
    }
    encoded = base64.b64encode(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    script = r'''
import base64, hashlib, json, sys
from unicorn import Uc, UC_ARCH_X86, UC_HOOK_INTR, UC_MODE_32, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_RSP

doc = json.loads(base64.b64decode(sys.argv[1], validate=True))
for row in doc["artifacts"]:
    payload = base64.b64decode(row["payload"], validate=True)
    assert hashlib.sha256(payload).hexdigest() == row["sha256"]
    assert all(0 <= int(value) <= len(payload) for value in row["placements"].values())
    if row["marker"] is not None:
        assert base64.b64decode(row["marker"], validate=True) in payload
assert len(doc["artifacts"]) == 11
print("R5B_STRUCTURAL_ROUNDTRIP:11")

def emulate(bits, row, scan_offset=0x100, expect_marker=True):
    mode = UC_MODE_32 if bits == 32 else UC_MODE_64
    uc = Uc(UC_ARCH_X86, mode)
    code_base, scan_base, output, stack = 0x100000, 0x200000, 0x300000, 0x400000
    hunter = base64.b64decode(row["hunter"], validate=True)
    egg_stage = base64.b64decode(row["egg_stage"], validate=True)
    marker = base64.b64decode(row["marker"], validate=True)
    uc.mem_map(code_base, 0x1000)
    uc.mem_map(scan_base, 0x2000)
    uc.mem_map(output, 0x1000)
    uc.mem_map(stack, 0x2000)
    uc.mem_write(code_base, hunter)
    uc.mem_write(scan_base + scan_offset, egg_stage)
    if bits == 32:
        uc.reg_write(UC_X86_REG_EDX, scan_base - 1)
        uc.reg_write(UC_X86_REG_ESP, stack + 0x1000)
    else:
        uc.reg_write(UC_X86_REG_RSP, stack + 0x1000)
    stopped = {"value": False}
    def interrupt(machine, number, _user):
        if number == 0x2e:
            machine.reg_write(UC_X86_REG_EAX, 0)
        elif number == 3:
            stopped["value"] = True
            machine.emu_stop()
        else:
            raise AssertionError("unexpected interrupt " + hex(number))
    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.emu_start(code_base, code_base + len(hunter), count=500000)
    assert stopped["value"]
    observed = bytes(uc.mem_read(output, len(marker)))
    if expect_marker:
        assert observed == marker
        print(f"R5B_UNICORN_X{bits}_MARKER:" + marker.decode("ascii"))
    else:
        assert observed == bytes(len(marker))
        print(f"R5B_UNICORN_X{bits}_BOUND_REFUSED")

emulate(32, doc["x86"])
emulate(64, doc["x64"])
emulate(64, doc["x64"], scan_offset=0xff8)
emulate(64, doc["x64"], scan_offset=0xff9, expect_marker=False)
'''
    result = _docker(["python3", "-c", script, encoded])
    assert result.returncode == 0, f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    assert "R5B_STRUCTURAL_ROUNDTRIP:11" in result.stdout
    assert "R5B_UNICORN_X32_MARKER:R5BX860!" in result.stdout
    assert result.stdout.count("R5B_UNICORN_X64_MARKER:R5BX640!") == 2
    assert "R5B_UNICORN_X64_BOUND_REFUSED" in result.stdout

