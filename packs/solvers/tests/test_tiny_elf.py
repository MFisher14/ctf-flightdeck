"""Behavioural tests for the B-109 tiny static-ELF / golf template library.

Nothing here executes an ELF.  The emitted images are checked two ways:

* structurally, by re-parsing the ELF and program headers with fixed spec
  offsets (independent of the builder's own placement table); and
* behaviourally, by a small test-side loader + x86 interpreter (``_run``) that
  maps the PT_LOAD segment the way the Linux loader does, starts at ``e_entry``
  and interprets the handful of x86 instructions the templates use, recording
  each system call (number and arguments, with ``write``/``execve`` buffers
  read from the mapped image).  It refuses any opcode it does not know, so a
  template that jumps into the wrong bytes fails loudly.  It is written from
  the Intel SDM / Linux syscall ABI, not from the builder's tables.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

from contract import BuildError, PayloadBuild  # noqa: E402
import tiny_elf  # noqa: E402


# --------------------------------------------------------------------------
# Header parsers (fixed ELF spec offsets).
# --------------------------------------------------------------------------

def _ehdr64(payload: bytes) -> dict:
    assert payload[:4] == b"\x7fELF"
    assert payload[4] == 2  # ELFCLASS64
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHIQQQIHHHHHH", payload, 16)
    return dict(e_type=e_type, e_machine=e_machine, e_entry=e_entry, e_phoff=e_phoff,
                e_phentsize=e_phentsize, e_phnum=e_phnum, e_shoff=e_shoff,
                e_ehsize=e_ehsize, e_shnum=e_shnum)


def _phdr64(payload: bytes, off: int) -> dict:
    (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from(
        "<IIQQQQQQ", payload, off)
    return dict(p_type=p_type, p_flags=p_flags, p_offset=p_offset, p_vaddr=p_vaddr,
                p_filesz=p_filesz, p_memsz=p_memsz, p_align=p_align)


def _ehdr32(payload: bytes) -> dict:
    assert payload[:4] == b"\x7fELF"
    assert payload[4] == 1  # ELFCLASS32
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHIIIIIHHHHHH", payload, 16)
    return dict(e_type=e_type, e_machine=e_machine, e_entry=e_entry, e_phoff=e_phoff,
                e_phentsize=e_phentsize, e_phnum=e_phnum, e_ehsize=e_ehsize)


def _phdr32(payload: bytes, off: int) -> dict:
    (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align) = struct.unpack_from(
        "<IIIIIIII", payload, off)
    return dict(p_type=p_type, p_offset=p_offset, p_vaddr=p_vaddr,
                p_filesz=p_filesz, p_memsz=p_memsz, p_flags=p_flags, p_align=p_align)


# --------------------------------------------------------------------------
# Test-side loader + x86 subset interpreter (the oracle).
# --------------------------------------------------------------------------

class _Fault(AssertionError):
    pass


def _load(payload: bytes) -> tuple[int, int, list[tuple[int, bytes, int]]]:
    """Return (bits, entry, segments) the way the Linux loader would map them."""
    if payload[:4] != b"\x7fELF":
        raise _Fault("bad magic")
    if payload[4] == 2:
        bits, machine = 64, 0x3E
        e_type, e_machine = struct.unpack_from("<HH", payload, 16)
        e_entry, e_phoff = struct.unpack_from("<QQ", payload, 24)
        e_phentsize, e_phnum = struct.unpack_from("<HH", payload, 54)
        want_phentsize = 56
    elif payload[4] == 1:
        bits, machine = 32, 0x03
        e_type, e_machine = struct.unpack_from("<HH", payload, 16)
        e_entry, e_phoff = struct.unpack_from("<II", payload, 24)
        e_phentsize, e_phnum = struct.unpack_from("<HH", payload, 42)
        want_phentsize = 32
    else:
        raise _Fault("bad EI_CLASS")
    if e_type != 2 or e_machine != machine:
        raise _Fault(f"e_type/e_machine {e_type}/{e_machine:#x} not an executable for this class")
    if e_phentsize != want_phentsize or not 1 <= e_phnum <= 16:
        raise _Fault("bad program header table")
    segments = []
    for index in range(e_phnum):
        off = e_phoff + index * e_phentsize
        if off + e_phentsize > len(payload):
            raise _Fault("program header outside the file")
        if bits == 64:
            p = _phdr64(payload, off)
        else:
            p = _phdr32(payload, off)
        if p["p_type"] != 1:
            continue
        if p["p_offset"] + p["p_filesz"] > len(payload) or p["p_memsz"] < p["p_filesz"]:
            raise _Fault("segment outside the file")
        if p["p_offset"] % 0x1000 != p["p_vaddr"] % 0x1000:
            raise _Fault("segment offset/vaddr not congruent mod page")
        data = payload[p["p_offset"]:p["p_offset"] + p["p_filesz"]]
        data += b"\x00" * (p["p_memsz"] - p["p_filesz"])
        segments.append((p["p_vaddr"], data, p["p_flags"]))
    if not segments:
        raise _Fault("no PT_LOAD")
    return bits, e_entry, segments


def _read(segments, addr: int, size: int, *, executable: bool = False) -> bytes:
    for vaddr, data, flags in segments:
        if vaddr <= addr and addr + size <= vaddr + len(data):
            if executable and not flags & 1:
                raise _Fault(f"fetch from non-executable segment at {addr:#x}")
            return data[addr - vaddr:addr - vaddr + size]
    raise _Fault(f"access outside the mapped image: {addr:#x}+{size}")


def _cstring(segments, addr: int) -> bytes:
    out = bytearray()
    while True:
        byte = _read(segments, addr + len(out), 1)[0]
        if byte == 0:
            return bytes(out)
        out.append(byte)
        if len(out) > 4096:
            raise _Fault("unterminated string")


EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI = range(8)


def _run(payload: bytes, *, initial: int = 0, max_steps: int = 64) -> list[tuple]:
    """Interpret the image from e_entry; return the syscalls made, in order.

    ``initial`` fills every general-purpose register except the stack pointer
    (Linux zeroes them; a non-zero fill proves a template does not depend on it).
    Interpretation stops after exit/execve or an unknown syscall.
    """
    bits, rip, segments = _load(payload)
    mask = (1 << bits) - 1
    regs = [initial & mask] * 8
    regs[ESP] = 0x7FFF0000
    stack: list[int] = []
    events: list[tuple] = []
    for _ in range(max_steps):
        op = _read(segments, rip, 1, executable=True)[0]
        if bits == 64 and op == 0x48:  # REX.W
            op2 = _read(segments, rip + 1, 1, executable=True)[0]
            if not 0xB8 <= op2 <= 0xBF:
                raise _Fault(f"unsupported REX.W opcode {op2:#x} at {rip:#x}")
            regs[op2 - 0xB8] = struct.unpack("<Q", _read(segments, rip + 2, 8, executable=True))[0]
            rip += 10
        elif 0xB8 <= op <= 0xBF:  # mov r32, imm32 (zero-extends in 64-bit mode)
            regs[op - 0xB8] = struct.unpack("<I", _read(segments, rip + 1, 4, executable=True))[0]
            rip += 5
        elif 0xB0 <= op <= 0xB3:  # mov r8(low), imm8
            reg = op - 0xB0
            regs[reg] = (regs[reg] & ~0xFF & mask) | _read(segments, rip + 1, 1, executable=True)[0]
            rip += 2
        elif op in (0x31, 0xFF):
            modrm = _read(segments, rip + 1, 1, executable=True)[0]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            if mod != 3:
                raise _Fault(f"memory operand at {rip:#x}")
            if op == 0x31:  # xor r/m32, r32
                regs[rm] = (regs[rm] ^ regs[reg]) & 0xFFFFFFFF
            elif reg == 0:  # inc r/m32
                regs[rm] = (regs[rm] + 1) & 0xFFFFFFFF
            else:
                raise _Fault(f"unsupported FF /{reg} at {rip:#x}")
            rip += 2
        elif op == 0x6A:  # push imm8 (sign-extended)
            stack.append(struct.unpack("<b", _read(segments, rip + 1, 1, executable=True))[0] & mask)
            rip += 2
        elif 0x50 <= op <= 0x57:
            stack.append(regs[op - 0x50])
            rip += 1
        elif 0x58 <= op <= 0x5F:
            if not stack:
                raise _Fault("pop from an empty stack")
            regs[op - 0x58] = stack.pop()
            rip += 1
        elif op == 0xEB:  # jmp rel8
            rel = struct.unpack("<b", _read(segments, rip + 1, 1, executable=True))[0]
            rip = rip + 2 + rel
        elif (bits == 64 and _read(segments, rip, 2, executable=True) == b"\x0f\x05") or (
                bits == 32 and _read(segments, rip, 2, executable=True) == b"\xcd\x80"):
            rip += 2
            if bits == 64:
                nr, args = regs[EAX], (regs[EDI], regs[ESI], regs[EDX])
                sys_write, sys_exit, sys_execve = 1, 60, 59
            else:
                nr, args = regs[EAX], (regs[EBX], regs[ECX], regs[EDX])
                sys_write, sys_exit, sys_execve = 4, 1, 11
            if nr == sys_write:
                data = _read(segments, args[1], args[2])
                events.append(("write", args[0], data))
                regs[EAX] = len(data)
            elif nr == sys_exit:
                events.append(("exit", args[0]))
                return events
            elif nr == sys_execve:
                events.append(("execve", _cstring(segments, args[0]), args[1], args[2]))
                return events
            else:
                events.append(("unknown-syscall", nr))
                return events
            if bits == 64:
                regs[ECX] = rip  # syscall clobbers rcx (and r11)
        else:
            raise _Fault(f"unsupported opcode {op:#x} at {rip:#x}")
    raise _Fault("step budget exhausted")


GARBAGE = 0xDEADBEEFCAFEBABE


# --------------------------------------------------------------------------
# build_tiny_elf: headers, placements, entry point.
# --------------------------------------------------------------------------

def test_amd64_header_is_a_valid_single_pt_load_elf() -> None:
    code = b"\x90\x90\xcc"
    build = tiny_elf.build_tiny_elf(code, architecture="amd64", base_address=0x400000)
    assert isinstance(build, PayloadBuild)
    payload = build.payload
    eh = _ehdr64(payload)
    assert eh["e_type"] == 2 and eh["e_machine"] == 0x3E
    assert eh["e_ehsize"] == 64 and eh["e_phentsize"] == 56 and eh["e_phnum"] == 1
    assert eh["e_shoff"] == 0 and eh["e_shnum"] == 0  # no section headers
    assert eh["e_phoff"] == 64
    ph = _phdr64(payload, eh["e_phoff"])
    assert ph["p_type"] == 1  # PT_LOAD
    assert ph["p_offset"] == 0 and ph["p_vaddr"] == 0x400000
    assert ph["p_filesz"] == ph["p_memsz"] == len(payload)
    assert ph["p_align"] == 0x1000 and ph["p_flags"] == 5  # r-x, not writable
    # entry points at the first code byte, right after the 120-byte header region.
    assert eh["e_entry"] == 0x400000 + 120
    assert payload[120:] == code


def test_i386_header_is_a_valid_single_pt_load_elf() -> None:
    code = b"\x31\xc0\xcc"
    build = tiny_elf.build_tiny_elf(code, architecture="i386")
    payload = build.payload
    eh = _ehdr32(payload)
    assert eh["e_type"] == 2 and eh["e_machine"] == 3
    assert eh["e_ehsize"] == 52 and eh["e_phentsize"] == 32 and eh["e_phoff"] == 52
    ph = _phdr32(payload, eh["e_phoff"])
    assert ph["p_type"] == 1 and ph["p_offset"] == 0
    assert ph["p_vaddr"] == 0x08048000 and ph["p_filesz"] == len(payload)
    assert ph["p_flags"] == 5
    assert eh["e_entry"] == 0x08048000 + 84
    assert payload[84:] == code


def test_writable_segment_sets_pf_w() -> None:
    build = tiny_elf.build_tiny_elf(b"\xcc", architecture="amd64", writable=True)
    ph = _phdr64(build.payload, 64)
    assert ph["p_flags"] == 7  # rwx
    assert build.metadata["segment_flags"] == "rwx"


# Spec offsets/widths of the recorded header fields (ELF64 / ELF32 gABI).
_FIELD_SPEC = {
    "amd64": {"e_entry": (24, 8), "e_phoff": (32, 8), "p_offset": (72, 8),
              "p_vaddr": (80, 8), "p_filesz": (96, 8), "p_memsz": (104, 8)},
    "i386": {"e_entry": (24, 4), "e_phoff": (28, 4), "p_offset": (56, 4),
             "p_vaddr": (60, 4), "p_filesz": (68, 4), "p_memsz": (72, 4)},
}


@pytest.mark.parametrize("arch", ("amd64", "i386"))
def test_field_placements_match_the_elf_spec_offsets(arch: str) -> None:
    build = tiny_elf.build_tiny_elf(b"\x90\xcc", architecture=arch, base_address=0x401000)
    for label, (offset, width) in _FIELD_SPEC[arch].items():
        assert build.placements[label] == offset, label
        assert build.widths[label] == width, label
    payload = build.payload
    parsed = _phdr64(payload, 64) if arch == "amd64" else _phdr32(payload, 52)
    value = lambda label: int.from_bytes(build.slice(label), "little")  # noqa: E731
    assert value("p_offset") == parsed["p_offset"] == 0
    assert value("p_vaddr") == parsed["p_vaddr"] == 0x401000
    assert value("p_filesz") == value("p_memsz") == len(payload)
    header = 120 if arch == "amd64" else 84
    assert value("e_entry") == 0x401000 + header
    assert value("e_phoff") == header - (56 if arch == "amd64" else 32)


@pytest.mark.parametrize("arch", ("amd64", "i386"))
def test_nonzero_entry_offset_starts_execution_there(arch: str) -> None:
    # Byte 0 is an opcode the interpreter refuses; execution must start at 1.
    exit_stub = (b"\xbf\x07\x00\x00\x00\xb8\x3c\x00\x00\x00\x0f\x05" if arch == "amd64"
                 else b"\xbb\x07\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80")
    build = tiny_elf.build_tiny_elf(b"\xcc" + exit_stub, architecture=arch, entry_offset=1)
    header = 120 if arch == "amd64" else 84
    assert build.placements["entry"] == header + 1
    assert _run(build.payload) == [("exit", 7)]
    with pytest.raises(_Fault, match="unsupported opcode 0xcc"):
        _run(tiny_elf.build_tiny_elf(b"\xcc" + exit_stub, architecture=arch).payload)


def test_entry_offset_bound_is_the_last_blob_byte() -> None:
    blob = b"\x90\x90\xcc"
    last = tiny_elf.build_tiny_elf(blob, architecture="amd64", entry_offset=len(blob) - 1)
    assert _ehdr64(last.payload)["e_entry"] == 0x400000 + 120 + len(blob) - 1
    with pytest.raises(tiny_elf.TinyElfError, match="entry_offset lies outside"):
        tiny_elf.build_tiny_elf(blob, architecture="amd64", entry_offset=len(blob))


def test_image_must_fit_the_i386_address_space() -> None:
    base = 0xFFFFF000
    fits = tiny_elf.build_tiny_elf(b"\x90" * (0x1000 - 84), architecture="i386", base_address=base)
    assert len(fits.payload) == 0x1000
    with pytest.raises(tiny_elf.TinyElfError, match="does not fit in the i386 address space"):
        tiny_elf.build_tiny_elf(b"\x90" * (0x1000 - 83), architecture="i386", base_address=base)


# --------------------------------------------------------------------------
# Templates, interpreted.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("arch", ("amd64", "i386"))
@pytest.mark.parametrize("code", (0, 1, 42, 255))
def test_exit_template_exits_with_the_requested_status(arch: str, code: int) -> None:
    build = tiny_elf.elf_template("exit", arch, exit_code=code)
    assert _run(build.payload, initial=GARBAGE) == [("exit", code)]


@pytest.mark.parametrize("arch", ("amd64", "i386"))
def test_write_message_writes_then_exits_zero(arch: str) -> None:
    build = tiny_elf.elf_template("write_message", arch, message="FLAG{demo}\n")
    assert _run(build.payload, initial=GARBAGE) == [
        ("write", 1, b"FLAG{demo}\n"), ("exit", 0)]
    base = int(build.metadata["load_address"], 16)
    msg_addr = int(build.metadata["message_address"], 16)
    assert build.payload[msg_addr - base:] == b"FLAG{demo}\n"


@pytest.mark.parametrize("arch", ("amd64", "i386"))
@pytest.mark.parametrize("path", ("/bin/sh", "/bin/cat"))
def test_execve_template_execs_the_appended_path_with_null_argv_envp(arch: str, path: str) -> None:
    build = tiny_elf.elf_template("execve_sh", arch, path=path)
    assert _run(build.payload, initial=GARBAGE) == [("execve", path.encode(), 0, 0)]
    base = int(build.metadata["load_address"], 16)
    path_addr = int(build.metadata["path_address"], 16)
    assert build.payload[path_addr - base:] == path.encode() + b"\x00"


def test_execve_template_code_is_not_claimed_null_free() -> None:
    # The fixed-width immediates contain NUL bytes; the docs must not say otherwise.
    build = tiny_elf.elf_template("execve_sh", "amd64")
    code = build.payload[int(build.metadata["header_size"]):]
    assert 0 in code[:-len(b"/bin/sh\x00")]
    assert "null-free" not in (tiny_elf.elf_template.__doc__ or "").lower()


@pytest.mark.parametrize("arch", ("amd64", "i386"))
def test_quine_writes_exactly_its_own_bytes_then_exits_zero(arch: str) -> None:
    build = tiny_elf.elf_template("quine", arch)
    events = _run(build.payload, initial=GARBAGE)
    assert events == [("write", 1, build.payload), ("exit", 0)]
    assert build.metadata["reproduces_self"] == "true"
    assert int(build.metadata["written_length"]) == len(build.payload)


def test_golf_quine_is_112_bytes_with_the_phdr_inside_the_ehdr() -> None:
    build = tiny_elf.elf_template("quine_golf", "amd64")
    payload = build.payload
    assert len(payload) == tiny_elf.GOLF_QUINE_SIZE == 112
    eh = _ehdr64(payload)
    assert eh["e_type"] == 2 and eh["e_machine"] == 0x3E
    assert eh["e_phoff"] == 0x38 and eh["e_phentsize"] == 56 and eh["e_phnum"] == 1
    ph = _phdr64(payload, 0x38)
    assert ph["p_type"] == 1 and ph["p_flags"] == 5
    assert ph["p_offset"] == 0 and ph["p_vaddr"] == 0x400000
    assert ph["p_filesz"] == ph["p_memsz"] == 112
    assert 0x38 + 56 == len(payload)  # the program header ends exactly at the file end
    # Code starts in e_ident's EI_OSABI byte, right after EI_VERSION.
    assert eh["e_entry"] == 0x400000 + 7
    assert payload[:7] == b"\x7fELF\x02\x01\x01"
    for label, (offset, width) in _FIELD_SPEC["amd64"].items():
        if label.startswith("p_"):
            offset = 0x38 + (offset - 64)
        assert build.placements[label] == offset and build.widths[label] == width, label


def test_golf_quine_writes_exactly_its_own_bytes_then_exits_zero() -> None:
    build = tiny_elf.elf_template("quine_golf", "amd64")
    # Linux zeroes the general-purpose registers at entry; the golf code relies on it.
    assert build.metadata["assumes_zeroed_registers"] == "true"
    assert _run(build.payload, initial=0) == [("write", 1, build.payload), ("exit", 0)]


def test_golf_quine_at_another_base_still_reproduces_itself() -> None:
    build = tiny_elf.elf_template("quine_golf", "amd64", base_address=0x10000)
    assert _ehdr64(build.payload)["e_entry"] == 0x10007
    assert _run(build.payload) == [("write", 1, build.payload), ("exit", 0)]


def test_interpreter_catches_a_quine_that_writes_one_byte_short() -> None:
    # The oracle is not vacuous: patch the golf quine's count immediate (112 -> 111).
    payload = bytearray(tiny_elf.elf_template("quine_golf", "amd64").payload)
    count_at = payload.index(b"\xb2\x70")
    payload[count_at + 1] = 111
    events = _run(bytes(payload))
    assert events[0][0] == "write" and events[0][2] != bytes(payload)


def test_golf_quine_is_amd64_only() -> None:
    with pytest.raises(tiny_elf.TinyElfError, match="not available for i386"):
        tiny_elf.elf_template("quine_golf", "i386")


# --------------------------------------------------------------------------
# 32-bit-immediate address limits.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("template,base", (
    ("quine", 0x100000000), ("write_message", 0x7FFF00000000), ("quine_golf", 0x100000000),
))
def test_imm32_templates_refuse_a_base_above_4gib(template: str, base: int) -> None:
    with pytest.raises(tiny_elf.TinyElfError, match="below 4 GiB"):
        tiny_elf.elf_template(template, "amd64", base_address=base, message=b"hi")


def test_imm32_templates_accept_the_highest_base_that_fits() -> None:
    base = 0x100000000 - 0x1000
    build = tiny_elf.elf_template("quine", "amd64", base_address=base)
    assert _run(build.payload) == [("write", 1, build.payload), ("exit", 0)]
    # Execve uses a 64-bit immediate, so a high base is fine there.
    high = tiny_elf.elf_template("execve_sh", "amd64", base_address=0x7FFF00000000)
    assert _run(high.payload) == [("execve", b"/bin/sh", 0, 0)]


def test_imm32_image_may_end_exactly_at_4gib_but_not_one_byte_past() -> None:
    # The image [base, base + size) fits 32-bit immediates when its last byte is
    # 0xFFFFFFFF, i.e. base + size == 4 GiB exactly; one more byte crosses over.
    base = (1 << 32) - 0x1000
    fill = 0x1000 - 120 - (22 + 12)  # header + write stub + exit stub
    message = bytes((i % 251) + 1 for i in range(fill))
    build = tiny_elf.elf_template("write_message", "amd64", base_address=base, message=message)
    assert base + len(build.payload) == 1 << 32
    assert _run(build.payload) == [("write", 1, message), ("exit", 0)]
    with pytest.raises(tiny_elf.TinyElfError, match="below 4 GiB"):
        tiny_elf.elf_template("write_message", "amd64", base_address=base,
                              message=message + b"!")


# --------------------------------------------------------------------------
# Failure paths.
# --------------------------------------------------------------------------

def test_bad_bytes_are_rejected_loudly() -> None:
    # 0x7f is in the ELF magic, so it can never be avoided: a loud failure.
    with pytest.raises(BuildError, match="forbidden"):
        tiny_elf.build_tiny_elf(b"\x90", architecture="amd64", bad_bytes={0x7F})
    with pytest.raises(BuildError, match="forbidden"):
        tiny_elf.elf_template("quine_golf", "amd64", bad_bytes={0x7F})


def test_input_validation_fails_closed() -> None:
    with pytest.raises(tiny_elf.TinyElfError, match="architecture"):
        tiny_elf.build_tiny_elf(b"\x90", architecture="sparc")
    with pytest.raises(tiny_elf.TinyElfError, match="page-aligned"):
        tiny_elf.build_tiny_elf(b"\x90", architecture="amd64", base_address=0x400001)
    with pytest.raises(tiny_elf.TinyElfError, match="1..1048576"):
        tiny_elf.build_tiny_elf(b"", architecture="amd64")
    with pytest.raises(tiny_elf.TinyElfError, match="entry_offset"):
        tiny_elf.build_tiny_elf(b"\x90\x90", architecture="amd64", entry_offset=9)
    with pytest.raises(tiny_elf.TinyElfError, match="unknown template"):
        tiny_elf.elf_template("rop", "amd64")
    with pytest.raises(tiny_elf.TinyElfError, match="exit_code"):
        tiny_elf.elf_template("exit", "amd64", exit_code=256)
    with pytest.raises(tiny_elf.TinyElfError, match="NUL"):
        tiny_elf.elf_template("execve_sh", "amd64", path="/bin\x00sh")


def test_available_templates_inventory() -> None:
    inv = tiny_elf.available_templates()
    assert set(inv) == {"amd64", "i386"}
    assert inv["amd64"] == tiny_elf.TEMPLATES == (
        "exit", "write_message", "execve_sh", "quine", "quine_golf")
    assert inv["i386"] == ("exit", "write_message", "execve_sh", "quine")
    for arch, names in inv.items():
        for name in names:  # every advertised template actually builds
            assert tiny_elf.elf_template(name, arch, message=b"x").payload[:4] == b"\x7fELF"


def test_assemble_fails_loudly_without_nasm(monkeypatch: pytest.MonkeyPatch) -> None:
    # No silent fallback: a missing assembler is a named, actionable error.
    monkeypatch.setattr(tiny_elf.shutil, "which", lambda name: None)
    with pytest.raises(tiny_elf.TinyElfError, match="nasm.*not found"):
        tiny_elf.assemble("nop", "amd64")
    # An unsupported backend is also refused, not quietly ignored.
    with pytest.raises(tiny_elf.TinyElfError, match="only the 'nasm'"):
        tiny_elf.assemble("nop", "amd64", assembler="gas")
    with pytest.raises(tiny_elf.TinyElfError, match="non-empty"):
        tiny_elf.assemble("   ", "amd64")


@pytest.mark.parametrize("source", (
    '%include "secret.inc"\nnop',
    'nop\n  %  INCLUDE "x"',
    'incbin "/some/file"',
    'data: INCBIN "f", 0, 4',
    '%pathsearch p "x"',
    '%depend "x"',
))
def test_assemble_refuses_file_reading_directives(source: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # nasm is "absent" here, so a refusal naming the directive proves the check
    # runs before the toolchain is looked up (and so before nasm could run).
    monkeypatch.setattr(tiny_elf.shutil, "which", lambda name: None)
    with pytest.raises(tiny_elf.TinyElfError, match="file-reading directive"):
        tiny_elf.assemble(source, "amd64")
    # The operator's own source may opt in; it then reaches the toolchain check.
    with pytest.raises(tiny_elf.TinyElfError, match="nasm.*not found"):
        tiny_elf.assemble(source, "amd64", trusted_source=True)


def test_assemble_allows_ordinary_source_past_the_directive_check(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiny_elf.shutil, "which", lambda name: None)
    # "included" / "incbins" are labels, not directives.
    with pytest.raises(tiny_elf.TinyElfError, match="nasm.*not found"):
        tiny_elf.assemble("included: nop\nincbins: nop\n%define X 1", "amd64")


@pytest.mark.parametrize("source", (
    # multi-line macro whose parameter pastes onto text: inc%1 -> incbin
    '%macro m 1\n  inc%1 "secret"\n%endmacro\nm bin',
    '%define X inc %+ bin\nX "f"',           # token pasting
    '%define A inc\n%[A]bin "f"',             # indirect macro name
    'mov eax, %!HOME',                       # environment read
    '%ifenv HOME\nnop\n%endif',
    "%deftok T 'nop'\nT",
    "%  DEFTOK T 'nop'\nT",                  # spaced, upper-case directive name
    "%strcat S 'a', 'b'",
    "%substr S 'xincbinx' 2, 6",
    "%define T %tok('nop')",
    '%push ctx\n%$x: nop\n%pop',
    'mov eax, %1',
    '%use altreg',
    'mov eax, 7 %% 3',
))
def test_assemble_refuses_token_building_constructs_on_untrusted_source(
        source: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # nasm is "absent": the refusal must come from the allowlist check, before nasm.
    monkeypatch.setattr(tiny_elf.shutil, "which", lambda name: None)
    with pytest.raises(tiny_elf.TinyElfError, match="outside the allowlist"):
        tiny_elf.assemble(source, "amd64")
    with pytest.raises(tiny_elf.TinyElfError, match="nasm.*not found"):
        tiny_elf.assemble(source, "amd64", trusted_source=True)


@pytest.mark.parametrize("source", (
    "%define X 1\n%assign Y X+1\nmov eax, Y",
    "%if 1\nnop\n%elif 2\nnop\n%else\nnop\n%endif",
    "%rep 3\nnop\n%endrep",
    "%IFDEF X\nnop\n%ENDIF",
    "%defstr S hello\n%strlen L S",
    "mov eax, 7 % 3",
    'db "100%", 0',
))
def test_assemble_allowlist_accepts_literal_token_directives(
        source: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tiny_elf.shutil, "which", lambda name: None)
    with pytest.raises(tiny_elf.TinyElfError, match="nasm.*not found"):
        tiny_elf.assemble(source, "amd64")


def test_assemble_runs_nasm_with_a_minimal_environment(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A stub "nasm" (not the real tool) writes its environment as the output
    # binary, so the bytes assemble() returns show what nasm would have seen.
    stub = tmp_path / "nasm"
    stub.write_text('#!/bin/sh\n/usr/bin/env > "$4"\n', encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setattr(tiny_elf.shutil, "which", lambda name: str(stub))
    monkeypatch.setenv("B109_CANARY_SECRET", "canary-value-7f3a")
    monkeypatch.setenv("NASMENV", "-DFROM_ENV")
    out = tiny_elf.assemble("nop", "amd64").decode("utf-8")
    env = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    assert "canary-value-7f3a" not in out and "B109_CANARY_SECRET" not in env
    assert "NASMENV" not in env
    assert env.get("LC_ALL") == "C" and env.get("PATH") == "/usr/bin:/bin"
    # Only the fixed keys, plus what /bin/sh itself adds.
    assert set(env) <= {"PATH", "LC_ALL", "PWD", "OLDPWD", "SHLVL", "_"}


@pytest.mark.needs_tool("nasm")
def test_assemble_round_trips_through_build_tiny_elf() -> None:
    # Assemble a real write/exit stub, wrap it, and interpret it; only runs where nasm exists.
    source = (
        "mov edi, 1\n"
        "mov esi, 0x400000 + 120 + msg - $$\n"
        "mov edx, 3\n"
        "mov eax, 1\n"
        "syscall\n"
        "mov edi, 0\n"
        "mov eax, 60\n"
        "syscall\n"
        "msg: db 'hi', 10\n"
    )
    code = tiny_elf.assemble(source, "amd64")
    assert isinstance(code, bytes) and code
    build = tiny_elf.build_tiny_elf(code, architecture="amd64")
    assert build.payload[120:] == code
    assert _run(build.payload) == [("write", 1, b"hi\n"), ("exit", 0)]
