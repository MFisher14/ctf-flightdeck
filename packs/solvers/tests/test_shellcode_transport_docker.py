"""Opt-in runtime proof for r5b decoders and bounded Linux egghunters.

The generated instructions execute only in Unicorn inside the already-local
``csctf-pwn:1`` image.  Docker is always invoked with ``--pull=never`` and
``--network none``, a read-only root, no capabilities, no-new-privileges, and
bounded PIDs/memory/time.  Stages only write fixed markers into emulator memory.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import shellcode_transport as transport  # noqa: E402


CODE = 0x100000
STACK = 0x200000
OUTPUT = 0x300000
VERIFY = os.environ.get("CTF_R5B_DOCKER_VERIFY") == "1"
DOCKER_ONLY = pytest.mark.skipif(
    not VERIFY,
    reason="set CTF_R5B_DOCKER_VERIFY=1 for fixed networkless Unicorn proof",
)


def _x86_stage(bits: int, marker: bytes) -> bytes:
    assert len(marker) == 8
    if bits == 32:
        return (
            b"\xB8" + marker[:4] + b"\xA3" + struct.pack("<I", OUTPUT)
            + b"\xB8" + marker[4:] + b"\xA3" + struct.pack("<I", OUTPUT + 4)
            + b"\xCC"
        )
    return b"\x48\xB8" + marker + b"\x48\xA3" + struct.pack("<Q", OUTPUT) + b"\xCC"


def _a64_load(register: int, value: int) -> bytes:
    words = []
    for halfword in range(4):
        immediate = (value >> (halfword * 16)) & 0xFFFF
        base = 0xD2800000 if halfword == 0 else 0xF2800000
        words.append(base | (halfword << 21) | (immediate << 5) | register)
    return b"".join(struct.pack("<I", word) for word in words)


def _aarch64_stage(marker: bytes) -> bytes:
    assert len(marker) == 8
    value = int.from_bytes(marker, "little")
    return (
        _a64_load(2, value)
        + _a64_load(3, OUTPUT)
        + struct.pack("<I", 0xF9000062)  # str x2, [x3]
        + struct.pack("<I", 0x14000000)  # b . (bounded by emulator count)
    )


def _document() -> dict[str, object]:
    xor_rows = []
    for arch, bits, marker, variant in (
        ("i386", 32, b"R5BXOR32", 0),
        ("amd64", 64, b"R5BXOR64", 2),
    ):
        stage = _x86_stage(bits, marker)
        build = transport.build_xor_decoder(
            stage, architecture=arch, bad_bytes={0, 10, 13},
            variant=variant, variant_seed=9,
        )
        xor_rows.append({
            "arch": arch,
            "payload": base64.b64encode(build.payload).decode(),
            "decoded": base64.b64encode(stage).decode(),
            "body_offset": build.placements["encoded_body"],
            "marker": base64.b64encode(marker).decode(),
        })

    hunter_rows = []
    hunter_specs = (
        ("i386", b"R5BEGG32", _x86_stage(32, b"R5BEGG32"), "access", 33, 0),
        ("amd64", b"R5BEGG64", _x86_stage(64, b"R5BEGG64"), "access", 21, 1),
        ("aarch64", b"R5BA64!!", _aarch64_stage(b"R5BA64!!"), "mapped", None, 1),
    )
    for arch, marker, stage, probe, syscall, variant in hunter_specs:
        kwargs = {}
        if syscall is not None:
            kwargs = {"access_syscall": syscall, "expected_efault": 14}
        build = transport.build_linux_egghunter(
            architecture=arch,
            tag=b"E5B!",
            stage=stage,
            payload_address=CODE,
            range_start=CODE,
            range_end=CODE + 0x1000,
            probe=probe,
            variant=variant,
            **kwargs,
        )
        hunter_rows.append({
            "arch": arch,
            "payload": base64.b64encode(build.payload).decode(),
            "marker": base64.b64encode(marker).decode(),
        })

    raw = b"R5B transport \x00\xff"
    transports = []
    for mode, variant in (("alphanumeric", 2), ("printable", 1)):
        build = transport.build_transport_encoding(raw, mode=mode, variant=variant)
        plan = json.loads(build.metadata["decoder_plan"])
        transports.append({
            "payload": base64.b64encode(build.payload).decode(),
            "codec": plan["codec"],
            "padding": plan["padding"],
            "expected": base64.b64encode(raw).decode(),
        })
    return {"xor": xor_rows, "hunters": hunter_rows, "transports": transports}


_SCRIPT = r'''import base64, json, sys
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_HOOK_INSN, UC_HOOK_INTR,
    UC_MODE_32, UC_MODE_64, UC_MODE_ARM,
)
from unicorn.arm64_const import UC_ARM64_REG_SP
from unicorn.x86_const import (
    UC_X86_INS_SYSCALL, UC_X86_REG_EAX, UC_X86_REG_ESP,
    UC_X86_REG_RAX, UC_X86_REG_RSP,
)

CODE, STACK, OUTPUT = 0x100000, 0x200000, 0x300000
doc = json.loads(base64.b64decode(sys.argv[1], validate=True))

def x86_machine(bits, payload, allow_probe):
    uc = Uc(UC_ARCH_X86, UC_MODE_32 if bits == 32 else UC_MODE_64)
    for address, size in ((CODE, 0x4000), (STACK, 0x4000), (OUTPUT, 0x1000)):
        uc.mem_map(address, size)
    uc.mem_write(CODE, payload)
    uc.reg_write(UC_X86_REG_ESP if bits == 32 else UC_X86_REG_RSP, STACK + 0x2000)
    stopped = {"value": False}
    def interrupt(machine, number, _user):
        if number == 0x80 and allow_probe and bits == 32:
            machine.reg_write(UC_X86_REG_EAX, 0)
        elif number == 3:
            stopped["value"] = True
            machine.emu_stop()
        else:
            raise AssertionError("unexpected interrupt " + hex(number))
    uc.hook_add(UC_HOOK_INTR, interrupt)
    if allow_probe and bits == 64:
        def syscall(machine, _user):
            machine.reg_write(UC_X86_REG_RAX, 0)
        uc.hook_add(UC_HOOK_INSN, syscall, None, 1, 0, UC_X86_INS_SYSCALL)
    return uc, stopped

for row in doc["xor"]:
    payload = base64.b64decode(row["payload"], validate=True)
    decoded = base64.b64decode(row["decoded"], validate=True)
    marker = base64.b64decode(row["marker"], validate=True)
    bits = 32 if row["arch"] == "i386" else 64
    uc, stopped = x86_machine(bits, payload, False)
    uc.emu_start(CODE, CODE + len(payload), count=100000)
    assert stopped["value"]
    assert bytes(uc.mem_read(OUTPUT, len(marker))) == marker
    assert bytes(uc.mem_read(CODE + row["body_offset"], len(decoded))) == decoded

for row in doc["hunters"]:
    payload = base64.b64decode(row["payload"], validate=True)
    marker = base64.b64decode(row["marker"], validate=True)
    if row["arch"] in {"i386", "amd64"}:
        bits = 32 if row["arch"] == "i386" else 64
        uc, stopped = x86_machine(bits, payload, True)
        uc.emu_start(CODE, CODE + len(payload), count=200000)
        assert stopped["value"]
    else:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for address, size in ((CODE, 0x4000), (STACK, 0x4000), (OUTPUT, 0x1000)):
            uc.mem_map(address, size)
        uc.mem_write(CODE, payload)
        uc.reg_write(UC_ARM64_REG_SP, STACK + 0x2000)
        uc.emu_start(CODE, CODE + len(payload), count=200000)
    assert bytes(uc.mem_read(OUTPUT, len(marker))) == marker

for row in doc["transports"]:
    payload = base64.b64decode(row["payload"], validate=True)
    expected = base64.b64decode(row["expected"], validate=True)
    codec = row["codec"]
    if codec == "base32-unpadded":
        decoded = base64.b32decode(payload + b"=" * row["padding"])
    elif codec == "base85":
        decoded = base64.b85decode(payload)
    elif codec == "ascii85":
        decoded = base64.a85decode(payload, adobe=False, foldspaces=False)
    else:
        decoded = bytes.fromhex(payload.decode("ascii"))
    assert decoded == expected

print("R5B_TRANSPORT_UNICORN_MARKERS:5")
print("R5B_TRANSPORT_CODECS:2")
'''


def _docker_argv(encoded: str) -> list[str]:
    return [
        "docker", "run", "--pull=never", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "csctf-pwn:1", "python3", "-c", _SCRIPT, encoded,
    ]


def test_runtime_manifest_is_complete_and_docker_command_is_fixed() -> None:
    document = _document()
    assert {row["arch"] for row in document["xor"]} == {"i386", "amd64"}
    assert {row["arch"] for row in document["hunters"]} == {"i386", "amd64", "aarch64"}
    assert len(document["transports"]) == 2
    encoded = base64.b64encode(json.dumps(document, sort_keys=True).encode()).decode()
    argv = _docker_argv(encoded)
    assert argv[:4] == ["docker", "run", "--pull=never", "--rm"]
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--pids-limit") + 1] == "64"
    assert argv[argv.index("--memory") + 1] == "256m"
    assert argv[argv.index("--platform") + 1] == "linux/amd64"
    assert "--pull=always" not in argv and "--pull=missing" not in argv


@DOCKER_ONLY
def test_decoders_and_hunters_reach_harmless_markers_only_in_unicorn() -> None:
    encoded = base64.b64encode(json.dumps(_document(), sort_keys=True).encode()).decode()
    completed = subprocess.run(
        _docker_argv(encoded), check=False, capture_output=True, text=True, timeout=90,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
    assert "R5B_TRANSPORT_UNICORN_MARKERS:5" in completed.stdout
    assert "R5B_TRANSPORT_CODECS:2" in completed.stdout
