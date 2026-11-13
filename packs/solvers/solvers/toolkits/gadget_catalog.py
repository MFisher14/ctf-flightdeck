"""Bounded, static gadget cataloguing for caller-supplied ELF bytes.

This module is deliberately a parser, not a runner: it never maps or executes the
input and has no networking surface.  Exact instruction encodings are catalogued
from executable ELF sections (or executable ``PT_LOAD`` segments when a section
table is absent).  The small semantic vocabulary is sufficient for the r5b chain
builders while preserving every matching address for caller-side policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Iterable


MAX_ELF_BYTES = 64 * 1024 * 1024
MAX_EXEC_BYTES = 16 * 1024 * 1024
MAX_GADGETS = 8192


class ELFParseError(ValueError):
    """Raised when a byte sequence is not a bounded, structurally valid ELF."""


@dataclass(frozen=True, order=True)
class Gadget:
    """One exact byte signature found in an executable file region."""

    address: int
    file_offset: int
    semantic: str
    raw: bytes
    stack_delta: int = 0
    clobbers: tuple[str, ...] = ()


@dataclass(frozen=True)
class GadgetCatalog:
    """Immutable catalog returned by :func:`catalog_elf`."""

    architecture: str
    bits: int
    endian: str
    elf_type: int
    entry: int
    gadgets: tuple[Gadget, ...]

    def find(self, *semantics: str) -> tuple[Gadget, ...]:
        """Return address-sorted gadgets matching any requested semantic."""

        wanted = set(semantics)
        return tuple(g for g in self.gadgets if g.semantic in wanted)

    def first(self, *semantics: str) -> Gadget | None:
        """Return the lowest-address matching gadget, or ``None``."""

        matches = self.find(*semantics)
        return matches[0] if matches else None

    def require(self, semantic: str) -> Gadget:
        """Return the first match or raise a deterministic diagnostic."""

        gadget = self.first(semantic)
        if gadget is None:
            raise LookupError(f"required gadget absent: {semantic}")
        return gadget

    def by_semantic(self) -> dict[str, tuple[int, ...]]:
        """Stable semantic-to-address projection for templates and reports."""

        grouped: dict[str, list[int]] = {}
        for gadget in self.gadgets:
            grouped.setdefault(gadget.semantic, []).append(gadget.address)
        return {key: tuple(values) for key, values in sorted(grouped.items())}


@dataclass(frozen=True)
class _Region:
    address: int
    file_offset: int
    data: bytes


_MACHINES = {
    3: "i386",
    8: "mips",
    40: "arm",
    62: "amd64",
    183: "aarch64",
    243: "riscv",
}


# semantic -> (bytes, stack delta after the terminal transfer, clobbers)
_X86_64 = {
    "ret": (b"\xc3", 8, ()),
    "leave ; ret": (b"\xc9\xc3", 16, ("rbp", "rsp")),
    "syscall": (b"\x0f\x05", 0, ("rcx", "r11")),
    "syscall ; ret": (b"\x0f\x05\xc3", 8, ("rcx", "r11")),
    "pop rax ; ret": (b"\x58\xc3", 16, ("rax",)),
    "pop rcx ; ret": (b"\x59\xc3", 16, ("rcx",)),
    "pop rdx ; ret": (b"\x5a\xc3", 16, ("rdx",)),
    "pop rbx ; ret": (b"\x5b\xc3", 16, ("rbx",)),
    "pop rsp ; ret": (b"\x5c\xc3", 16, ("rsp",)),
    "pop rbp ; ret": (b"\x5d\xc3", 16, ("rbp",)),
    "pop rsi ; ret": (b"\x5e\xc3", 16, ("rsi",)),
    "pop rdi ; ret": (b"\x5f\xc3", 16, ("rdi",)),
    "pop r8 ; ret": (b"\x41\x58\xc3", 16, ("r8",)),
    "pop r9 ; ret": (b"\x41\x59\xc3", 16, ("r9",)),
    "pop r10 ; ret": (b"\x41\x5a\xc3", 16, ("r10",)),
    "pop r11 ; ret": (b"\x41\x5b\xc3", 16, ("r11",)),
    "pop r12 ; ret": (b"\x41\x5c\xc3", 16, ("r12",)),
    "pop r13 ; ret": (b"\x41\x5d\xc3", 16, ("r13",)),
    "pop r14 ; ret": (b"\x41\x5e\xc3", 16, ("r14",)),
    "pop r15 ; ret": (b"\x41\x5f\xc3", 16, ("r15",)),
    "xchg rax, rsp ; ret": (b"\x48\x94\xc3", 8, ("rax", "rsp")),
    "mov rsp, rax ; ret": (b"\x48\x89\xc4\xc3", 8, ("rsp",)),
    "mov rdi, rax ; ret": (b"\x48\x89\xc7\xc3", 8, ("rdi",)),
    "jmp rax": (b"\xff\xe0", 0, ()),
    "jmp rbx": (b"\xff\xe3", 0, ()),
    "jmp rcx": (b"\xff\xe1", 0, ()),
    "jmp rdx": (b"\xff\xe2", 0, ()),
    "call rax": (b"\xff\xd0", 8, ()),
    "call rbx": (b"\xff\xd3", 8, ()),
    "call rcx": (b"\xff\xd1", 8, ()),
    "call rdx": (b"\xff\xd2", 8, ()),
    "csu pop rbx rbp r12 r13 r14 r15 ; ret": (
        b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3",
        56,
        ("rbx", "rbp", "r12", "r13", "r14", "r15"),
    ),
    "csu call [r12+rbx*8] (r13d,r14,r15)": (
        b"\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc",
        0,
        ("rdi", "rsi", "rdx"),
    ),
    "csu call [r15+rbx*8] (r12d,r13,r14)": (
        b"\x4c\x89\xf2\x4c\x89\xee\x44\x89\xe7\x41\xff\x14\xdf",
        0,
        ("rdi", "rsi", "rdx"),
    ),
}

_I386 = {
    "ret": (b"\xc3", 4, ()),
    "leave ; ret": (b"\xc9\xc3", 8, ("ebp", "esp")),
    "int 0x80": (b"\xcd\x80", 0, ()),
    "int 0x80 ; ret": (b"\xcd\x80\xc3", 4, ()),
    "pop eax ; ret": (b"\x58\xc3", 8, ("eax",)),
    "pop ecx ; ret": (b"\x59\xc3", 8, ("ecx",)),
    "pop edx ; ret": (b"\x5a\xc3", 8, ("edx",)),
    "pop ebx ; ret": (b"\x5b\xc3", 8, ("ebx",)),
    "pop esp ; ret": (b"\x5c\xc3", 8, ("esp",)),
    "pop ebp ; ret": (b"\x5d\xc3", 8, ("ebp",)),
    "pop esi ; ret": (b"\x5e\xc3", 8, ("esi",)),
    "pop edi ; ret": (b"\x5f\xc3", 8, ("edi",)),
    "xchg eax, esp ; ret": (b"\x94\xc3", 4, ("eax", "esp")),
    "jmp eax": (b"\xff\xe0", 0, ()),
    "jmp ebx": (b"\xff\xe3", 0, ()),
    "call eax": (b"\xff\xd0", 4, ()),
    "call ebx": (b"\xff\xd3", 4, ()),
}


def _risc_signatures(arch: str, endian: str) -> dict[str, tuple[bytes, int, tuple[str, ...]]]:
    little = endian == "little"
    if arch == "aarch64":
        values = {
            "ret": bytes.fromhex("c0035fd6"),
            "svc #0": bytes.fromhex("010000d4"),
            "br x16": bytes.fromhex("00021fd6"),
            "blr x16": bytes.fromhex("00023fd6"),
            "br x17": bytes.fromhex("20021fd6"),
        }
    elif arch == "arm":
        values = {
            "bx lr": bytes.fromhex("1eff2fe1"),
            "svc #0": bytes.fromhex("000000ef"),
            "pop {pc}": bytes.fromhex("04f09de4"),
        }
    elif arch == "mips":
        values = {
            "jr ra": bytes.fromhex("0800e003"),
            "syscall": bytes.fromhex("0c000000"),
            "jalr t9": bytes.fromhex("09f82003"),
        }
    elif arch == "riscv":
        values = {
            "ret": bytes.fromhex("67800000"),
            "ecall": bytes.fromhex("73000000"),
            "jr t0": bytes.fromhex("67800200"),
        }
    else:
        return {}
    if not little:
        values = {name: raw[::-1] for name, raw in values.items()}
    return {name: (raw, 0, ()) for name, raw in values.items()}


def _read_source(source: bytes | bytearray | memoryview | str | Path) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        path = Path(source)
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_ELF_BYTES + 1)
        except OSError as exc:
            raise ELFParseError(f"cannot read ELF source: {exc}") from exc
    if len(data) > MAX_ELF_BYTES:
        raise ELFParseError(f"ELF exceeds {MAX_ELF_BYTES} bytes")
    return data


def _unpack_from(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ELFParseError("ELF table extends past end of file")
    return struct.unpack_from(fmt, data, offset)


def _elf_identity(data: bytes) -> dict[str, int | str]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ELFParseError("not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endian is None:
        raise ELFParseError("unsupported ELF class or byte order")
    ec = "<" if endian == "little" else ">"
    etype, machine = _unpack_from(ec + "HH", data, 16)
    if bits == 64:
        if len(data) < 64:
            raise ELFParseError("truncated ELF64 header")
        entry, phoff, shoff = _unpack_from(ec + "QQQ", data, 24)
        phentsize, phnum, shentsize, shnum = _unpack_from(ec + "HHHH", data, 54)
    else:
        entry, phoff, shoff = _unpack_from(ec + "III", data, 24)
        phentsize, phnum, shentsize, shnum = _unpack_from(ec + "HHHH", data, 42)
    return {
        "bits": bits,
        "endian": endian,
        "ec": ec,
        "etype": etype,
        "machine": machine,
        "entry": entry,
        "phoff": phoff,
        "phentsize": phentsize,
        "phnum": phnum,
        "shoff": shoff,
        "shentsize": shentsize,
        "shnum": shnum,
    }


def _regions_from_sections(data: bytes, ident: dict[str, int | str]) -> list[_Region]:
    bits, ec = int(ident["bits"]), str(ident["ec"])
    shoff, entsize, count = (int(ident[key]) for key in ("shoff", "shentsize", "shnum"))
    expected = 64 if bits == 64 else 40
    if not shoff or not count or entsize < expected or count > 65535:
        return []
    regions: list[_Region] = []
    total = 0
    for index in range(count):
        off = shoff + index * entsize
        if bits == 64:
            row = _unpack_from(ec + "IIQQQQIIQQ", data, off)
            _name, stype, flags, address, file_off, size = row[:6]
        else:
            row = _unpack_from(ec + "IIIIIIIIII", data, off)
            _name, stype, flags, address, file_off, size = row[:6]
        if not (flags & 0x4) or not size or stype == 8:  # SHF_EXECINSTR; ignore SHT_NOBITS
            continue
        if file_off + size > len(data):
            raise ELFParseError("executable section extends past end of file")
        remaining = MAX_EXEC_BYTES - total
        if remaining <= 0:
            break
        take = min(size, remaining)
        regions.append(_Region(address, file_off, data[file_off:file_off + take]))
        total += take
    return regions


def _regions_from_segments(data: bytes, ident: dict[str, int | str]) -> list[_Region]:
    bits, ec = int(ident["bits"]), str(ident["ec"])
    phoff, entsize, count = (int(ident[key]) for key in ("phoff", "phentsize", "phnum"))
    expected = 56 if bits == 64 else 32
    if not phoff or not count or entsize < expected or count > 65535:
        return []
    regions: list[_Region] = []
    total = 0
    for index in range(count):
        off = phoff + index * entsize
        if bits == 64:
            ptype, flags, file_off, vaddr, _paddr, filesz, _memsz, _align = _unpack_from(
                ec + "IIQQQQQQ", data, off
            )
        else:
            ptype, file_off, vaddr, _paddr, filesz, _memsz, flags, _align = _unpack_from(
                ec + "IIIIIIII", data, off
            )
        if ptype != 1 or not (flags & 1) or not filesz:  # PT_LOAD and PF_X
            continue
        if file_off + filesz > len(data):
            raise ELFParseError("executable segment extends past end of file")
        remaining = MAX_EXEC_BYTES - total
        if remaining <= 0:
            break
        take = min(filesz, remaining)
        regions.append(_Region(vaddr, file_off, data[file_off:file_off + take]))
        total += take
    return regions


def _iter_hits(haystack: bytes, needle: bytes) -> Iterable[int]:
    start = 0
    while True:
        found = haystack.find(needle, start)
        if found < 0:
            return
        yield found
        start = found + 1


def catalog_elf(
    source: bytes | bytearray | memoryview | str | Path,
    *,
    load_bias: int = 0,
    max_gadgets: int = MAX_GADGETS,
) -> GadgetCatalog:
    """Statically search a supplied ELF and return an exact gadget catalog.

    ``load_bias`` lets a caller rebase PIE/shared-object virtual addresses after
    obtaining a legitimate leak.  It is arithmetic only and is never inferred.
    """

    if isinstance(load_bias, bool) or not isinstance(load_bias, int) or load_bias < 0:
        raise ELFParseError("load_bias must be a non-negative integer")
    if isinstance(max_gadgets, bool) or not isinstance(max_gadgets, int) or not 1 <= max_gadgets <= MAX_GADGETS:
        raise ELFParseError(f"max_gadgets must be in 1..{MAX_GADGETS}")
    data = _read_source(source)
    ident = _elf_identity(data)
    arch = _MACHINES.get(int(ident["machine"]), f"em_{ident['machine']}")
    regions = _regions_from_sections(data, ident) or _regions_from_segments(data, ident)
    if not regions:
        raise ELFParseError("ELF has no bounded executable file region")
    if arch == "amd64":
        signatures = _X86_64
    elif arch == "i386":
        signatures = _I386
    else:
        signatures = _risc_signatures(arch, str(ident["endian"]))
    if not signatures:
        raise ELFParseError(f"unsupported gadget architecture: {arch}")

    found: list[Gadget] = []
    seen: set[tuple[int, str]] = set()
    for region in regions:
        for semantic, (raw, delta, clobbers) in signatures.items():
            for offset in _iter_hits(region.data, raw):
                # Fixed-width RISC encodings are only instructions at their
                # architectural alignment; x86 deliberately permits mid-byte
                # entry points because those are real alternate decodings.
                if arch in {"arm", "aarch64", "mips", "riscv"} and offset % 4:
                    continue
                key = (region.address + offset + load_bias, semantic)
                if key in seen:
                    continue
                seen.add(key)
                found.append(Gadget(
                    address=key[0],
                    file_offset=region.file_offset + offset,
                    semantic=semantic,
                    raw=raw,
                    stack_delta=delta,
                    clobbers=tuple(clobbers),
                ))
                if len(found) > max_gadgets:
                    raise ELFParseError(f"gadget count exceeds caller cap {max_gadgets}")
    found.sort(key=lambda item: (item.address, -len(item.raw), item.semantic))
    return GadgetCatalog(
        architecture=arch,
        bits=int(ident["bits"]),
        endian=str(ident["endian"]),
        elf_type=int(ident["etype"]),
        entry=int(ident["entry"]) + load_bias,
        gadgets=tuple(found),
    )


def select_addresses(catalog: GadgetCatalog, semantics: Iterable[str]) -> dict[str, int]:
    """Resolve requested semantics to lowest exact addresses, never guesses."""

    result: dict[str, int] = {}
    for semantic in semantics:
        result[semantic] = catalog.require(semantic).address
    return result

