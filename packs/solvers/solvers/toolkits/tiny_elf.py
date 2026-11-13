"""Offline tiny static-ELF / golf template library for constrained pwn payloads.

B-109 fallback.  The constrained-shellcode item asks for two building blocks:
badchar-avoiding encoders (already provided by :mod:`shellcode_transport` and
:mod:`multiarch`) and a *tiny-ELF / golf template library* for the easy cases.
This module is that library.  It assembles minimal statically-mapped
``ET_EXEC`` executables around a caller-supplied code+data blob, and ships a
small catalogue of ready-made templates (exit, write-a-message, execve
``/bin/sh``, and a self-reproducing *quine*) for amd64 and i386, plus a 112-byte
header-overlap golf quine for amd64 (``quine_golf``) whose program header sits
inside the ELF header and whose code lives in fields the Linux loader ignores.

Design rules, matching the rest of the toolkit:

* Nothing here executes, maps, links, or spawns anything.  Every builder only
  *serializes bytes* and records where each field landed, returning a
  :class:`contract.PayloadBuild`.
* No external assembler is required for the templates: the ELF headers and the
  template code are emitted directly with :mod:`struct`, so the library works in
  a bare environment and never silently installs a toolchain.
* The one optional entry that *would* need an assembler, :func:`assemble`
  (NASM ``-f bin`` for arbitrary source), fails loudly with a named reason and a
  ``needs_tool`` hint when ``nasm`` is absent.  It never falls back silently.

The genuinely hard cases B-109 names -- persistent-register / per-step-reset /
self-patching-syscall shellcode under a byte budget -- are a bespoke constraint
solver and are left to the agent, by design (``automatable: no``).
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

try:
    from contract import BuildError, PayloadBuild, reject_bad_bytes
except ImportError:  # pragma: no cover - package-style import
    from .contract import BuildError, PayloadBuild, reject_bad_bytes


class TinyElfError(BuildError):
    """A requested ELF or template cannot be represented under the constraints."""


# ELF e_machine / class constants for the two supported architectures.
_ARCHES = {
    # name: (elf_class, e_machine, default_base, endian)
    "amd64": (2, 0x3E, 0x400000, "<"),
    "i386": (1, 0x03, 0x08048000, "<"),
}
_ALIASES = {
    "x86-64": "amd64", "x86_64": "amd64", "x64": "amd64", "amd64": "amd64",
    "x86": "i386", "i386": "i386", "x86-32": "i386", "ia32": "i386",
}

_PF_X, _PF_W, _PF_R = 1, 2, 4
_PAGE = 0x1000
MAX_BLOB = 1 << 20
MAX_MESSAGE = 1 << 16


def _arch(name: str) -> str:
    if not isinstance(name, str):
        raise TinyElfError("architecture must be text")
    try:
        return _ALIASES[name.strip().lower()]
    except KeyError as exc:
        raise TinyElfError("architecture must be amd64/x86-64 or i386/x86") from exc


def _blob(value: bytes | bytearray, *, name: str, maximum: int = MAX_BLOB) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TinyElfError(f"{name} must be bytes")
    raw = bytes(value)
    if not raw or len(raw) > maximum:
        raise TinyElfError(f"{name} must contain 1..{maximum} bytes")
    return raw


def _base(arch: str, base_address: int | None) -> int:
    default = _ARCHES[arch][2]
    if base_address is None:
        return default
    if isinstance(base_address, bool) or not isinstance(base_address, int):
        raise TinyElfError("base_address must be an integer")
    bits = 64 if arch == "amd64" else 32
    if not 0 < base_address < (1 << bits):
        raise TinyElfError(f"base_address must be a positive {bits}-bit address")
    if base_address % _PAGE != 0:
        raise TinyElfError("base_address must be page-aligned (multiple of 0x1000)")
    return base_address


def build_tiny_elf(
    blob: bytes | bytearray,
    *,
    architecture: str,
    base_address: int | None = None,
    entry_offset: int = 0,
    writable: bool = False,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Wrap ``blob`` in a minimal single-``PT_LOAD`` static ``ET_EXEC`` ELF.

    The whole file is mapped at ``base_address`` with ``p_offset == 0`` so the
    executable image byte-for-byte equals the file -- the property the quine
    template relies on.  ``entry_offset`` is a byte offset into ``blob`` for the
    entry point (the code is placed immediately after the headers).  Section
    headers are omitted entirely; only the program header the loader needs is
    emitted.  ``writable=True`` adds ``PF_W`` for self-modifying code.
    """

    arch = _arch(architecture)
    code = _blob(blob, name="blob")
    base = _base(arch, base_address)
    elf_class, machine, _default, endian = _ARCHES[arch]

    if isinstance(entry_offset, bool) or not isinstance(entry_offset, int) or entry_offset < 0:
        raise TinyElfError("entry_offset must be a non-negative integer")
    if entry_offset >= len(code):
        raise TinyElfError("entry_offset lies outside the blob")
    header_len = _HEADER_LEN[arch]
    address_limit = 1 << (64 if arch == "amd64" else 32)
    if base + header_len + len(code) > address_limit:
        raise TinyElfError(
            f"image of {header_len + len(code)} bytes at {base:#x} does not fit in the "
            f"{arch} address space")

    flags = _PF_R | _PF_X | (_PF_W if writable else 0)

    if arch == "amd64":
        ehdr_size, phdr_size = 64, 56
        header_size = ehdr_size + phdr_size
        file_size = header_size + len(code)
        entry = base + header_size + entry_offset
        e_ident = b"\x7fELF" + bytes([elf_class, 1, 1, 0]) + b"\x00" * 8
        ehdr = e_ident + struct.pack(
            endian + "HHIQQQIHHHHHH",
            2,            # e_type = ET_EXEC
            machine,      # e_machine
            1,            # e_version
            entry,        # e_entry
            ehdr_size,    # e_phoff
            0,            # e_shoff
            0,            # e_flags
            ehdr_size,    # e_ehsize
            phdr_size,    # e_phentsize
            1,            # e_phnum
            0, 0, 0,      # e_shentsize, e_shnum, e_shstrndx
        )
        phdr = struct.pack(
            endian + "IIQQQQQQ",
            1,            # p_type = PT_LOAD
            flags,        # p_flags
            0,            # p_offset
            base,         # p_vaddr
            base,         # p_paddr
            file_size,    # p_filesz
            file_size,    # p_memsz
            _PAGE,        # p_align
        )
        field_places = {
            "e_entry": (24, 8), "e_phoff": (32, 8),
            "p_filesz": (ehdr_size + 32, 8), "p_memsz": (ehdr_size + 40, 8),
            "p_vaddr": (ehdr_size + 16, 8), "p_offset": (ehdr_size + 8, 8),
        }
    else:  # i386
        ehdr_size, phdr_size = 52, 32
        header_size = ehdr_size + phdr_size
        file_size = header_size + len(code)
        entry = base + header_size + entry_offset
        e_ident = b"\x7fELF" + bytes([elf_class, 1, 1, 0]) + b"\x00" * 8
        ehdr = e_ident + struct.pack(
            endian + "HHIIIIIHHHHHH",
            2, machine, 1,
            entry,        # e_entry
            ehdr_size,    # e_phoff
            0,            # e_shoff
            0,            # e_flags
            ehdr_size,    # e_ehsize
            phdr_size,    # e_phentsize
            1,            # e_phnum
            0, 0, 0,
        )
        phdr = struct.pack(
            endian + "IIIIIIII",
            1,            # p_type = PT_LOAD
            0,            # p_offset
            base,         # p_vaddr
            base,         # p_paddr
            file_size,    # p_filesz
            file_size,    # p_memsz
            flags,        # p_flags
            _PAGE,        # p_align
        )
        field_places = {
            "e_entry": (24, 4), "e_phoff": (28, 4),
            "p_offset": (ehdr_size + 4, 4), "p_vaddr": (ehdr_size + 8, 4),
            "p_filesz": (ehdr_size + 16, 4), "p_memsz": (ehdr_size + 20, 4),
        }

    assert len(ehdr) == ehdr_size and len(phdr) == phdr_size
    payload = ehdr + phdr + code
    assert len(payload) == file_size
    reject_bad_bytes(payload, bad_bytes)

    placements = {
        "elf_header": 0,
        "program_header": ehdr_size,
        "code": header_size,
        "entry": header_size + entry_offset,
        "end": file_size,
    }
    widths = {"elf_header": ehdr_size, "program_header": phdr_size, "code": len(code)}
    for label, (offset, width) in field_places.items():
        placements[label] = offset
        widths[label] = width

    return PayloadBuild(
        payload,
        placements,
        widths,
        architecture=arch,
        strategy="tiny-static-elf",
        base_address=base,
        metadata={
            "entry": hex(entry),
            "load_address": hex(base),
            "file_size": str(file_size),
            "header_size": str(header_size),
            "segment_flags": {5: "r-x", 7: "rwx"}.get(flags, str(flags)),
            "delivery": "none",
            "executable": "true",
        },
    )


# --------------------------------------------------------------------------
# Template code generators.  Every immediate is emitted at a fixed width so the
# emitted code length is a constant that does not depend on the operand value;
# that lets an appended string's load address (or the quine's file size) be
# computed up-front instead of by fixed-point search.
# --------------------------------------------------------------------------

def _amd64_exit(code: int) -> bytes:
    #   mov edi, code ; mov eax, 60 ; syscall
    return b"\xbf" + struct.pack("<I", code) + b"\xb8" + struct.pack("<I", 60) + b"\x0f\x05"


def _i386_exit(code: int) -> bytes:
    #   mov ebx, code ; mov eax, 1 ; int 0x80
    return b"\xbb" + struct.pack("<I", code) + b"\xb8" + struct.pack("<I", 1) + b"\xcd\x80"


def _amd64_write(addr: int, length: int) -> bytes:
    #   mov edi,1 ; mov esi,addr ; mov edx,length ; mov eax,1 ; syscall
    return (b"\xbf" + struct.pack("<I", 1)
            + b"\xbe" + struct.pack("<I", addr)
            + b"\xba" + struct.pack("<I", length)
            + b"\xb8" + struct.pack("<I", 1) + b"\x0f\x05")


def _i386_write(addr: int, length: int) -> bytes:
    #   mov eax,4 ; mov ebx,1 ; mov ecx,addr ; mov edx,length ; int 0x80
    return (b"\xb8" + struct.pack("<I", 4)
            + b"\xbb" + struct.pack("<I", 1)
            + b"\xb9" + struct.pack("<I", addr)
            + b"\xba" + struct.pack("<I", length) + b"\xcd\x80")


# execve(path, NULL, NULL); the path string is appended by the template so no
# writable stack is needed.  rsi/rdx (or ecx/edx) = NULL.  The code is NOT
# NUL-free (the fixed-width immediates contain 0x00 bytes): for NUL-free
# shellcode use shellcode_transport's encoders instead of lifting these bytes.
def _amd64_execve_prologue(path_addr: int) -> bytes:
    #   mov rdi, path_addr ; xor esi,esi ; xor edx,edx ; mov eax,59 ; syscall
    return (b"\x48\xbf" + struct.pack("<Q", path_addr)
            + b"\x31\xf6\x31\xd2"
            + b"\xb8" + struct.pack("<I", 59) + b"\x0f\x05")


def _i386_execve_prologue(path_addr: int) -> bytes:
    #   mov ebx, path_addr ; xor ecx,ecx ; xor edx,edx ; mov eax,11 ; int 0x80
    return (b"\xbb" + struct.pack("<I", path_addr)
            + b"\x31\xc9\x31\xd2"
            + b"\xb8" + struct.pack("<I", 11) + b"\xcd\x80")


_EXIT = {"amd64": _amd64_exit, "i386": _i386_exit}
_WRITE = {"amd64": _amd64_write, "i386": _i386_write}
_EXECVE = {"amd64": _amd64_execve_prologue, "i386": _i386_execve_prologue}
# Emitted code length is constant per arch; computed once so dependent
# addresses are known before the real immediates are substituted.
_WRITE_LEN = {"amd64": len(_amd64_write(0, 0)), "i386": len(_i386_write(0, 0))}
_EXIT_LEN = {"amd64": len(_amd64_exit(0)), "i386": len(_i386_exit(0))}
_EXECVE_LEN = {"amd64": len(_amd64_execve_prologue(0)), "i386": len(_i386_execve_prologue(0))}
_HEADER_LEN = {"amd64": 120, "i386": 84}


def _message(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeError as exc:
            raise TinyElfError("message is not valid UTF-8") from exc
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise TinyElfError("message must be bytes or text")
    if not raw or len(raw) > MAX_MESSAGE:
        raise TinyElfError(f"message must contain 1..{MAX_MESSAGE} bytes")
    return raw


TEMPLATES = ("exit", "write_message", "execve_sh", "quine", "quine_golf")
# Templates each architecture supports; quine_golf is amd64-only.
_ARCH_TEMPLATES = {
    "amd64": TEMPLATES,
    "i386": ("exit", "write_message", "execve_sh", "quine"),
}
_IMM32_LIMIT = 1 << 32


def _require_imm32_image(arch: str, base: int, size: int, template: str) -> None:
    """Templates that load addresses with ``mov r32, imm32`` need a sub-4-GiB image."""

    if base + size > _IMM32_LIMIT:
        raise TinyElfError(
            f"template {template!r} loads addresses as 32-bit immediates; on {arch} "
            f"base_address + image size ({base:#x} + {size}) must stay below 4 GiB")


# Header-overlap golf quine (amd64), after the 112-byte limit of the
# "elves-can-be-spooky-too" challenge.  The program header starts at 0x38, so
# p_type (=1) doubles as e_phnum=1 / e_shentsize=0 and p_flags (=5) as
# e_shnum / e_shstrndx; it ends exactly at byte 112.  The code runs from the
# EI_OSABI/padding bytes of e_ident (0x07..0x0f), which the Linux loader
# ignores, and jumps into the equally ignored e_shoff / e_flags / e_ehsize bytes
# (0x28..0x35).  It relies on Linux zeroing the general-purpose registers at
# process entry (ELF_PLAT_INIT on x86-64).
GOLF_QUINE_SIZE = 112
_GOLF_PHOFF = 0x38
_GOLF_HEAD = (0x07, 9)    # (offset, room): e_ident[EI_OSABI..EI_PAD], code + jmp
_GOLF_TAIL = (0x28, 14)   # (offset, room): e_shoff, e_flags, e_ehsize


def _amd64_golf_quine(base: int) -> tuple[bytes, dict[str, int], dict[str, int]]:
    head_at, head_room = _GOLF_HEAD
    tail_at, tail_room = _GOLF_TAIL
    jmp_from = head_at + head_room             # address after the 2-byte jmp
    head = (b"\xbe" + struct.pack("<I", base)  # mov esi, base     (buf = image)
            + b"\xff\xc7"                      # inc edi           (fd = 1)
            + b"\xeb" + bytes([tail_at - jmp_from]))  # jmp tail
    tail = (b"\xb2" + bytes([GOLF_QUINE_SIZE])  # mov dl, 112      (count)
            + b"\xff\xc0"                      # inc eax           (SYS_write = 1)
            + b"\x0f\x05"                      # syscall
            + b"\x31\xff"                      # xor edi, edi      (status 0)
            + b"\x6a\x3c\x58"                  # push 60 ; pop rax (SYS_exit)
            + b"\x0f\x05")                     # syscall
    if len(head) != head_room or len(tail) > tail_room:
        raise TinyElfError("internal golf-quine layout invariant failed")
    image = bytearray(GOLF_QUINE_SIZE)
    image[0:7] = b"\x7fELF" + bytes([2, 1, 1])  # magic, ELFCLASS64, LSB, EV_CURRENT
    image[head_at:head_at + head_room] = head
    struct.pack_into("<HHI", image, 0x10, 2, 0x3E, 1)  # e_type, e_machine, e_version
    struct.pack_into("<QQ", image, 0x18, base + head_at, _GOLF_PHOFF)  # e_entry, e_phoff
    image[tail_at:tail_at + len(tail)] = tail
    struct.pack_into("<H", image, 0x36, 56)  # e_phentsize
    struct.pack_into("<IIQQQQQQ", image, _GOLF_PHOFF,
                     1, _PF_R | _PF_X, 0, base, base,
                     GOLF_QUINE_SIZE, GOLF_QUINE_SIZE, _PAGE)
    placements = {
        "elf_header": 0, "program_header": _GOLF_PHOFF,
        "code_head": head_at, "code_tail": tail_at, "entry": head_at,
        "e_entry": 0x18, "e_phoff": 0x20,
        "p_offset": _GOLF_PHOFF + 8, "p_vaddr": _GOLF_PHOFF + 16,
        "p_filesz": _GOLF_PHOFF + 32, "p_memsz": _GOLF_PHOFF + 40,
        "end": GOLF_QUINE_SIZE,
    }
    widths = {
        "elf_header": 64, "program_header": 56,
        "code_head": head_room, "code_tail": len(tail),
        "e_entry": 8, "e_phoff": 8, "p_offset": 8, "p_vaddr": 8,
        "p_filesz": 8, "p_memsz": 8,
    }
    return bytes(image), placements, widths


def elf_template(
    name: str,
    architecture: str,
    *,
    base_address: int | None = None,
    message: bytes | bytearray | str = b"",
    exit_code: int = 0,
    path: str = "/bin/sh",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build one ready-made tiny-ELF template (see :data:`TEMPLATES`).

    * ``exit`` -- ``exit(exit_code)``.
    * ``write_message`` -- ``write(1, message)`` then ``exit(0)``.
    * ``execve_sh`` -- ``execve(path, NULL, NULL)`` (default /bin/sh); the code
      contains NUL bytes, so it is not NUL-free shellcode.
    * ``quine`` -- ``write(1, <whole file>)`` then ``exit(0)``; the emitted ELF
      reproduces its own bytes exactly, proven by construction (``p_offset==0``
      and the written length equals ``file_size``).
    * ``quine_golf`` (amd64 only) -- the same quine in exactly 112 bytes, with
      the program header overlapping the ELF header and the code in header
      fields the loader ignores; assumes Linux's zeroed registers at entry.

    ``write_message``, ``quine`` and ``quine_golf`` load addresses as 32-bit
    immediates, so their image must lie below 4 GiB.
    """

    arch = _arch(architecture)
    if name not in TEMPLATES:
        raise TinyElfError(f"unknown template {name!r}; choose {', '.join(TEMPLATES)}")
    if name not in _ARCH_TEMPLATES[arch]:
        raise TinyElfError(f"template {name!r} is not available for {arch}")
    base = _base(arch, base_address)
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise TinyElfError("exit_code must be an integer in 0..255")

    if name == "exit":
        blob = _EXIT[arch](exit_code)
        build = build_tiny_elf(blob, architecture=arch, base_address=base, bad_bytes=bad_bytes)
        return _retag(build, "tiny-elf-template-exit", {"template": "exit",
                                                        "exit_code": str(exit_code)})

    if name == "write_message":
        raw = _message(message)
        code_len = _WRITE_LEN[arch] + _EXIT_LEN[arch]
        msg_addr = base + _HEADER_LEN[arch] + code_len
        _require_imm32_image(arch, base, _HEADER_LEN[arch] + code_len + len(raw), name)
        blob = _WRITE[arch](msg_addr, len(raw)) + _EXIT[arch](0) + raw
        build = build_tiny_elf(blob, architecture=arch, base_address=base, bad_bytes=bad_bytes)
        return _retag(build, "tiny-elf-template-write", {
            "template": "write_message",
            "message_address": hex(msg_addr),
            "message_length": str(len(raw)),
        })

    if name == "execve_sh":
        if not isinstance(path, str) or not path:
            raise TinyElfError("path must be non-empty text")
        path_bytes = path.encode("utf-8")
        if b"\x00" in path_bytes or len(path_bytes) > 255:
            raise TinyElfError("path must be 1..255 bytes without an embedded NUL")
        path_bytes += b"\x00"
        code_len = _EXECVE_LEN[arch]
        path_addr = base + _HEADER_LEN[arch] + code_len
        blob = _EXECVE[arch](path_addr) + path_bytes
        build = build_tiny_elf(blob, architecture=arch, base_address=base, bad_bytes=bad_bytes)
        return _retag(build, "tiny-elf-template-execve", {
            "template": "execve_sh",
            "path": path,
            "path_address": hex(path_addr),
        })

    if name == "quine_golf":
        _require_imm32_image(arch, base, GOLF_QUINE_SIZE, name)
        payload, placements, widths = _amd64_golf_quine(base)
        reject_bad_bytes(payload, bad_bytes)
        return PayloadBuild(
            payload, placements, widths,
            architecture=arch, strategy="tiny-elf-template-quine-golf",
            base_address=base,
            metadata={
                "template": "quine_golf",
                "entry": hex(base + _GOLF_HEAD[0]),
                "load_address": hex(base),
                "file_size": str(GOLF_QUINE_SIZE),
                "program_header_offset": hex(_GOLF_PHOFF),
                "segment_flags": "r-x",
                "reproduces_self": "true",
                "written_length": str(GOLF_QUINE_SIZE),
                "assumes_zeroed_registers": "true",
                "delivery": "none",
                "executable": "true",
            },
        )

    # name == "quine": the file size is fully determined before emission because
    # the write+exit code length is a per-arch constant independent of operands.
    file_size = _HEADER_LEN[arch] + _WRITE_LEN[arch] + _EXIT_LEN[arch]
    _require_imm32_image(arch, base, file_size, name)
    blob = _WRITE[arch](base, file_size) + _EXIT[arch](0)
    build = build_tiny_elf(blob, architecture=arch, base_address=base, bad_bytes=bad_bytes)
    if len(build.payload) != file_size:
        raise TinyElfError("internal quine size invariant failed")
    return _retag(build, "tiny-elf-template-quine", {
        "template": "quine",
        "reproduces_self": "true",
        "written_length": str(file_size),
    })


def _retag(build: PayloadBuild, strategy: str, extra: dict[str, str]) -> PayloadBuild:
    metadata = dict(build.metadata)
    metadata.update(extra)
    return PayloadBuild(
        build.payload,
        dict(build.placements),
        dict(build.widths),
        architecture=build.architecture,
        strategy=strategy,
        base_address=build.base_address,
        metadata=metadata,
    )


def available_templates() -> dict[str, tuple[str, ...]]:
    """Machine-readable inventory for triage / reporting."""

    return {arch: _ARCH_TEMPLATES[arch] for arch in _ARCHES}


# --------------------------------------------------------------------------
# Optional: assemble arbitrary NASM source to raw bytes for the harder cases.
# This is the one entry that depends on an external toolchain; it fails loudly
# with a named reason and a needs_tool hint rather than installing anything.
# --------------------------------------------------------------------------

_BITS = {"amd64": "BITS 64", "i386": "BITS 32"}
# NASM constructs that read local files into the output or the dependency list.
_FILE_READ_DIRECTIVES = re.compile(
    r"(%\s*(include|pathsearch|depend)\b|\bincbin\b)", re.IGNORECASE)
# Untrusted source gets an allowlist of preprocessor directives, not just the
# denylist above: anything that can *build* a token from pieces (``%+`` pasting,
# ``%[...]`` indirection, ``%deftok``/``%strcat``/``%substr``/``%tok``, and
# multi-line macros, whose parameters concatenate with neighbouring text, e.g.
# ``inc%1``) could assemble ``incbin`` or ``%include`` past a literal match, and
# ``%!VAR`` / ``%ifenv`` read the environment.  Only directives that work on
# literal tokens are allowed; every other ``%`` construct is refused.
# A directive name may follow "%" after whitespace ("%  include"); a punctuation
# construct ("%+", "%1", "%%") must follow it directly, so "7 % 3" is modulo.
_PP_CONSTRUCT = re.compile(r"%(?:\s*([A-Za-z_][A-Za-z0-9_]*)|([^\sA-Za-z_]))")
_UNTRUSTED_PP_ALLOWED = frozenset({
    "define", "idefine", "xdefine", "ixdefine", "undef", "assign", "iassign",
    "defstr", "idefstr", "strlen",
    "if", "elif", "else", "endif",
    "ifdef", "ifndef", "elifdef", "elifndef",
    "ifnum", "ifnnum", "elifnum", "elifnnum",
    "ifidn", "ifidni", "ifnidn", "ifnidni", "elifidn", "elifidni",
    "ifstr", "ifnstr", "elifstr", "elifnstr", "ifid", "ifnid", "elifid", "elifnid",
    "rep", "endrep", "exitrep",
    "error", "warning", "fatal",
})
# ``%`` followed by one of these is a token-building or macro-only construct.
_UNTRUSTED_PP_PUNCT_REFUSED = frozenset("+[!$?{%0123456789")
# nasm reads options from $NASMENV; it gets a fixed, minimal environment.
_NASM_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def _refuse_untrusted_constructs(source: str) -> None:
    found = _FILE_READ_DIRECTIVES.search(source)
    if found:
        raise TinyElfError(
            f"assembler source uses the file-reading directive {found.group(0)!r}; "
            "refused for untrusted source (pass trusted_source=True for your own source)")
    for match in _PP_CONSTRUCT.finditer(source):
        name, punct = match.group(1), match.group(2)
        if name is not None and name.lower() in _UNTRUSTED_PP_ALLOWED:
            continue
        if punct is not None and punct not in _UNTRUSTED_PP_PUNCT_REFUSED:
            continue  # e.g. "% 3" (modulo by a literal) or "%(" -- no token building
        raise TinyElfError(
            f"assembler source uses the preprocessor construct {match.group(0)!r}, which is "
            "outside the allowlist for untrusted source (it can build tokens, read the "
            "environment or define macros); pass trusted_source=True for your own source")


def assemble(source: str, architecture: str, *, assembler: str = "nasm",
             trusted_source: bool = False) -> bytes:
    """Assemble NASM ``source`` to a flat binary blob (``nasm -f bin``).

    No linker runs and nothing is executed; ``nasm`` only emits machine code.
    When ``nasm`` is not on PATH this raises :class:`TinyElfError` naming the
    missing tool -- it never silently installs or substitutes a toolchain.  The
    result is suitable for :func:`build_tiny_elf`.

    Source may be derived from challenge data, so unless the caller passes
    ``trusted_source=True`` for source it wrote itself, the file-reading
    directives (``%include``, ``%pathsearch``, ``%depend``, ``incbin``) are
    refused and only an allowlist of preprocessor directives that work on literal
    tokens is accepted (no ``%+``, ``%[``, ``%!``, ``%deftok``, ``%strcat``,
    ``%substr``, ``%macro``, ...), so a file read cannot be assembled from pieces.
    nasm always runs with a fixed minimal environment (no ``$NASMENV``, no
    inherited secrets for ``%!VAR``) and its cwd in a private temp directory.
    """

    arch = _arch(architecture)
    if not isinstance(source, str) or not source.strip():
        raise TinyElfError("assembler source must be non-empty text")
    if not trusted_source:
        _refuse_untrusted_constructs(source)
    if assembler != "nasm":
        raise TinyElfError("only the 'nasm' assembler backend is supported")
    tool = shutil.which("nasm")
    if tool is None:
        raise TinyElfError(
            "assembler 'nasm' not found on PATH; install it as a human step "
            "(needs_tool: nasm) -- this library never installs toolchains")
    directive = _BITS[arch]
    with tempfile.TemporaryDirectory() as workdir:
        src = Path(workdir) / "payload.asm"
        out = Path(workdir) / "payload.bin"
        src.write_text(directive + "\n" + source + "\n", encoding="utf-8")
        try:
            completed = subprocess.run(
                [tool, "-f", "bin", "-o", str(out), str(src)],
                capture_output=True, timeout=60, check=False, cwd=workdir,
                env=dict(_NASM_ENV),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TinyElfError(f"nasm invocation failed: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()
            raise TinyElfError(f"nasm reported an error: {detail}")
        data = out.read_bytes()
    if not data:
        raise TinyElfError("nasm produced an empty binary")
    return data


__all__ = [
    "TinyElfError",
    "build_tiny_elf",
    "elf_template",
    "available_templates",
    "assemble",
    "TEMPLATES",
    "GOLF_QUINE_SIZE",
]
