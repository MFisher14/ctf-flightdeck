"""x86-64 glibc pointer-guard oracle using real FS:0x30 and setjmp slots."""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "csctf-pwn:1"


C_SOURCE = r"""
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>

static jmp_buf state;
static void target(void) { }

static uintptr_t guard_value(void) {
    uintptr_t value;
    __asm__("mov %%fs:0x30, %0" : "=r"(value));
    return value;
}

static uintptr_t reference_mangle(uintptr_t value) {
    __asm__("xor %%fs:0x30, %0; rol $0x11, %0" : "+r"(value));
    return value;
}

static uintptr_t reference_demangle(uintptr_t value) {
    __asm__("ror $0x11, %0; xor %%fs:0x30, %0" : "+r"(value));
    return value;
}

int main(void) {
    uintptr_t pointer = (uintptr_t)&target;
    uintptr_t mangled = reference_mangle(pointer);
    if (setjmp(state) != 0) return 2;
    uintptr_t *words = (uintptr_t *)state;
    printf("PTR %lx %lx %lx\n", (unsigned long)guard_value(),
           (unsigned long)pointer, (unsigned long)mangled);
    printf("JMP %lx %lx %lx %lx %lx\n", (unsigned long)(uintptr_t)state,
           (unsigned long)words[6], (unsigned long)words[7],
           (unsigned long)reference_demangle(words[6]),
           (unsigned long)reference_demangle(words[7]));
    return 0;
}
"""


ORACLE = r"""
import ctypes
import subprocess
import sys

subprocess.run(
    ["gcc", "-O0", "-fno-pie", "-no-pie", "-fcf-protection=none",
     "-o", "guard", "guard.c"],
    check=True,
)
lines = subprocess.check_output(["./guard"], text=True).splitlines()
ptr = lines[0].split()
jmp = lines[1].split()
assert ptr[0] == "PTR" and jmp[0] == "JMP"
guard, pointer, stored = (int(item, 16) for item in ptr[1:])
state, stored_rsp, stored_rip, saved_rsp, saved_rip = (
    int(item, 16) for item in jmp[1:]
)

libc = ctypes.CDLL(None)
libc.gnu_get_libc_version.restype = ctypes.c_char_p
parts = libc.gnu_get_libc_version().decode().split(".")
version = ".".join(parts[:2])
assert 35 <= int(parts[1]) <= 41

sys.path.insert(0, "/repo/solvers/toolkits")
import pwndepth_pointer_guard as pg

assert pg.mangle_pointer(pointer, guard) == stored
assert pg.demangle_pointer(stored, guard) == pointer
plan = pg.build_jmpbuf_control_plan(
    glibc_version=version,
    rsp_slot_address=state + 6 * 8,
    rip_slot_address=state + 7 * 8,
    saved_rsp=saved_rsp,
    saved_rip=saved_rip,
    pointer_guard=guard,
)
assert int.from_bytes(plan.rsp_payload, "little") == stored_rsp
assert int.from_bytes(plan.rip_payload, "little") == stored_rip
assert pg.verify_jmpbuf_control(
    plan.rsp_payload, plan.rip_payload,
    glibc_version=version,
    rsp_slot_address=plan.rsp_slot_address,
    rip_slot_address=plan.rip_slot_address,
    saved_rsp=saved_rsp,
    saved_rip=saved_rip,
    pointer_guard=guard,
)
print("PWNDEPTH_POINTER_GUARD_DOCKER_ORACLE_OK", version)
"""


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def test_real_pointer_guard_and_jmpbuf_slots_in_pwn_container(tmp_path: Path) -> None:
    if not _docker_ready():
        pytest.skip(f"local {IMAGE} image is unavailable")
    (tmp_path / "guard.c").write_text(textwrap.dedent(C_SOURCE), encoding="utf-8")
    (tmp_path / "oracle.py").write_text(textwrap.dedent(ORACLE), encoding="utf-8")
    command = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "512m", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
        "-v", f"{ROOT}:/repo:ro", "-v", f"{tmp_path}:/work:rw",
        "-w", "/work", IMAGE, "python3", "oracle.py",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PWNDEPTH_POINTER_GUARD_DOCKER_ORACLE_OK" in result.stdout
