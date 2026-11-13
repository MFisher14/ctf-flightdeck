"""Sacrificial emulator verification for the r5b multi-architecture bytes.

Normal collection only validates the inert ELF envelopes.  Set
``CTF_R5B_DOCKER_VERIFY=1`` to execute the generated write/exit shellcode in
the already-local multiarch image.  The container invocation is deliberately
fixed to ``--pull=never --network none`` with a read-only root, no capabilities,
bounded resources, and a read-only fixture mount.
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import multiarch as multi  # noqa: E402


VERIFY = os.environ.get("CTF_R5B_DOCKER_VERIFY") == "1"
DOCKER_ONLY = pytest.mark.skipif(
    not VERIFY,
    reason="set CTF_R5B_DOCKER_VERIFY=1 for networkless --pull=never emulation",
)


def _elf32(arch: str, code: bytes) -> bytes:
    spec = multi.ARCHITECTURES[arch]
    endian = "<" if spec.endian == "little" else ">"
    encoding = 1 if spec.endian == "little" else 2
    machine = 40 if arch.startswith("arm") else 8
    flags = 0x05000002 if arch.startswith("arm") else 0x50001007
    base = 0x00010000 if arch.startswith("arm") else 0x00400000
    code_offset = 0x100
    total = code_offset + len(code)
    ident = b"\x7fELF" + bytes((1, encoding, 1, 0)) + bytes(8)
    header = struct.pack(
        endian + "16sHHIIIIIHHHHHH",
        ident, 2, machine, 1, base + code_offset, 52, 0, flags,
        52, 32, 1, 0, 0, 0,
    )
    segment = struct.pack(
        endian + "IIIIIIII",
        1, 0, base, base, total, total, 5, 0x1000,
    )
    return header + segment + bytes(code_offset - len(header) - len(segment)) + code


def _elf64(arch: str, code: bytes) -> bytes:
    machine = 183 if arch == "aarch64" else 243
    base = 0x00400000 if arch == "aarch64" else 0x00010000
    code_offset = 0x100
    total = code_offset + len(code)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 2, machine, 1, base + code_offset, 64, 0, 0,
        64, 56, 1, 0, 0, 0,
    )
    segment = struct.pack(
        "<IIQQQQQQ",
        1, 5, 0, base, base, total, total, 0x1000,
    )
    return header + segment + bytes(code_offset - len(header) - len(segment)) + code


def _wrap(arch: str, code: bytes) -> bytes:
    return _elf32(arch, code) if multi.ARCHITECTURES[arch].bits == 32 else _elf64(arch, code)


@pytest.mark.parametrize("arch", tuple(multi.ARCHITECTURES))
def test_minimal_elf_envelope_round_trips_payload_bytes(arch: str) -> None:
    shellcode = multi.build_marker_shellcode(arch, f"R5B_{arch}_STATIC\n")
    image = _wrap(arch, shellcode.payload)
    spec = multi.ARCHITECTURES[arch]
    endian = "little" if spec.endian == "little" else "big"
    assert image.startswith(b"\x7fELF")
    assert image[4] == (1 if spec.bits == 32 else 2)
    assert image[5] == (1 if spec.endian == "little" else 2)
    entry_offset = 24 if spec.bits == 32 else 24
    entry_width = 4 if spec.bits == 32 else 8
    assert int.from_bytes(image[entry_offset:entry_offset + entry_width], endian) > 0
    assert image[0x100:] == shellcode.payload
    assert image.endswith(shellcode.slice("marker"))


@DOCKER_ONLY
def test_all_available_qemu_emulators_execute_exact_marker(tmp_path: Path) -> None:
    expected = bytearray()
    commands: list[str] = []
    for arch, spec in multi.ARCHITECTURES.items():
        marker = f"R5B_EMULATED_{arch}\n".encode()
        build = multi.build_marker_shellcode(arch, marker)
        fixture = tmp_path / f"r5b_{arch}.elf"
        fixture.write_bytes(_wrap(arch, build.payload))
        fixture.chmod(0o755)
        commands.append(f"{spec.emulator} /work/{fixture.name}")
        expected.extend(marker)

    argv = [
        "docker", "run", "--pull=never", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "--mount",
        f"type=bind,src={tmp_path},dst=/work,readonly",
        "csctf-pwn-multiarch:1", "sh", "-ec", "\n".join(commands),
    ]
    completed = subprocess.run(argv, check=False, capture_output=True, timeout=90)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout == bytes(expected)


@DOCKER_ONLY
def test_all_available_qemu_emulators_execve_benign_marker_fixture(tmp_path: Path) -> None:
    """Exercise execve bytes against one inert script inside the same sandbox."""

    marker = b"R5B_EXECVE_EMULATED_OK\n"
    target = tmp_path / "r5b_exec_marker"
    target.write_bytes(b"#!/bin/sh\nprintf 'R5B_EXECVE_EMULATED_OK\\n'\n")
    target.chmod(0o755)
    commands: list[str] = []
    for arch, spec in multi.ARCHITECTURES.items():
        build = multi.build_execve_shellcode(arch, "/work/r5b_exec_marker")
        fixture = tmp_path / f"r5b_execve_{arch}.elf"
        fixture.write_bytes(_wrap(arch, build.payload))
        fixture.chmod(0o755)
        commands.append(f"{spec.emulator} /work/{fixture.name}")

    argv = [
        "docker", "run", "--pull=never", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "--mount",
        f"type=bind,src={tmp_path},dst=/work,readonly",
        "csctf-pwn-multiarch:1", "sh", "-ec", "\n".join(commands),
    ]
    completed = subprocess.run(argv, check=False, capture_output=True, timeout=90)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout == marker * len(multi.ARCHITECTURES)
