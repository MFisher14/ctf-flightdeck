#!/usr/bin/env python3
"""Day 1 binary sample: a plain C ELF (header fields, section table, symbol table, one tiny function).

Usage:
  python3 solvers/binary/d01.py <elf> [...]

Everything is read from the bytes with pyelftools and capstone; nothing about a
particular variant is assumed. The sample is recognised by its dNN-/dayNN- name
or, failing that, by its custom `.huntress` section.

Answer conventions the Game Master accepted on the Day 4 base (2026-10-04):

  analysis_elf_class      "ELF64"            ("ELF" + class bits)
  analysis_machine        "x86-64"           (friendly name, not EM_X86_64)
  analysis_elf_type       "ET_EXEC"          (raw e_type name; "EXEC" is rejected)
  analysis_endianness     "little"
  analysis_section_names  every section name in header order, INCLUDING the
                          empty name of the null section at index 0
  analysis_symbols        every non-empty name in .symtab, table order
                          (FILE symbols and name@VERSION entries included,
                          .dynsym excluded)
  analysis_disassembly    the recover_code function only, one string per
                          instruction, Intel syntax, "mnemonic operands" with
                          ", " between operands, numbers in DECIMAL, nothing
                          after an operand-less mnemonic:
                          ["mov eax, 8100","ret"]
"""
import io
import re
import sys

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM
from elftools.elf.elffile import ELFFile

import binlib

ELF_MAGIC = b"\x7fELF"
# Functions the C runtime contributes; what is left over belongs to the sample's own source.
CRT_FUNCS = {"_start", "_init", "_fini", "_dl_relocate_static_pie", "__libc_csu_init", "__libc_csu_fini",
             "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy"}
# Only x86-64 has been judged for ELF. "i386" is what the judge accepted for the
# Day 3 PE's machine; the rest follow the same lowercase style and are unconfirmed.
MACHINE = {"EM_X86_64": "x86-64", "EM_386": "i386", "EM_AARCH64": "aarch64", "EM_ARM": "arm",
           "EM_RISCV": "riscv", "EM_MIPS": "mips", "EM_PPC64": "ppc64", "EM_PPC": "ppc"}
HEX = re.compile(r"0x[0-9a-f]+")
BRANCHES = ("j", "call", "loop")


def symtab_of(elf):
    sec = elf.get_section_by_name(".symtab")
    return list(sec.iter_symbols()) if sec is not None else []


def own_functions(elf):
    """Defined FUNC symbols that do not come from the C runtime, in symbol-table order."""
    return [s for s in symtab_of(elf)
            if s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] != "SHN_UNDEF" and s.name not in CRT_FUNCS]


def designated(elf):
    """The sample's analysis function: recover_code, else its own function other than main."""
    funcs = own_functions(elf)
    named = [s for s in funcs if s.name == "recover_code"]
    rest = [s for s in funcs if s.name != "main"]
    return (named or rest or funcs or [None])[0]


def instructions(elf, sym):
    """Capstone instructions (with operand detail) for one function symbol."""
    if sym is None or not sym["st_size"]:
        return []
    sec = elf.get_section(sym["st_shndx"])
    start = sym["st_value"] - sec["sh_addr"]
    code = sec.data()[start:start + sym["st_size"]]
    md = Cs(CS_ARCH_X86, CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32)
    md.detail = True
    return list(md.disasm(code, sym["st_value"]))


def signed(value: int, size: int) -> int:
    """Read an immediate the way C reads the constant: two's complement in its operand size."""
    bits = 8 * size
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def render(insn) -> str:
    """One instruction as "mnemonic operands" with every number in base 10.

    The judge's listing prints `mov eax, 8100`, not `mov eax, 0x1fa4`. An
    immediate is printed as the signed value of its operand size, so that
    `return -1;` reads `mov eax, -1` just as `return 8100;` reads
    `mov eax, 8100`. Branch targets are addresses, not constants, and keep
    capstone's hex.
    """
    ops = insn.op_str
    if not ops:
        return insn.mnemonic
    if insn.mnemonic.startswith(BRANCHES):
        return f"{insn.mnemonic} {ops}"
    imms = {o.imm & (1 << 64) - 1: signed(o.imm, o.size) for o in insn.operands if o.type == X86_OP_IMM}

    def decimal(m):
        value = int(m.group(0), 16)
        return str(imms.get(value, value))

    return f"{insn.mnemonic} {HEX.sub(decimal, ops)}"


def returned_constant(elf):
    """The value the designated function loads into eax before returning, or None."""
    for insn in instructions(elf, designated(elf)):
        if insn.mnemonic == "mov" and insn.op_str.startswith(("eax, ", "rax, ")):
            imm = [o for o in insn.operands if o.type == X86_OP_IMM]
            if imm:
                return signed(imm[0].imm, imm[0].size)
        if insn.mnemonic == "xor" and insn.op_str == "eax, eax":
            return 0
    return None


def analyze(data: bytes) -> dict:
    """Every field this sample can answer, keyed the way the question ids name them."""
    elf = ELFFile(io.BytesIO(data))
    hdr = elf.header
    marker = elf.get_section_by_name(".huntress")
    target = designated(elf)
    constant = returned_constant(elf)
    return {
        "analysis_elf_class": f"ELF{elf.elfclass}",
        "analysis_machine": MACHINE.get(hdr["e_machine"], hdr["e_machine"]),
        "analysis_elf_type": hdr["e_type"],
        "analysis_endianness": "little" if elf.little_endian else "big",
        "analysis_section_names": binlib.compact([s.name for s in elf.iter_sections()]),
        "analysis_symbols": binlib.compact([s.name for s in symtab_of(elf) if s.name]),
        "analysis_disassembly": binlib.compact([render(i) for i in instructions(elf, target)]),
        # Asked on Days 1-2 with these documented formats; kept in case the fields return.
        "analysis_marker": marker.data().split(b"\x00")[0].decode("utf-8", "replace") if marker is not None else "none",
        "analysis_has_symtab": "true" if elf.get_section_by_name(".symtab") is not None else "false",
        "analysis_exported_symbol": target.name if target is not None else "none",
        "analysis_recover_code": str(constant) if constant is not None else "none",
        "analysis_entry_point": f"0x{hdr['e_entry']:x}",
    }


def pick_sample(files: dict):
    named = [s for s in binlib.day_files(files, 1) if s[1][:4] == ELF_MAGIC]
    if named:
        return named
    # Content recognition, PREFIX-SCOPED: only files named for day 1 or for no day at all are
    # considered (binlib.prefix_scoped never returns another day's named file), so a day-1 member
    # wrapped so its ELF magic is not at offset 0 can never be replaced by another prefix's ELF
    # that happens to carry a `.huntress` section. The old `binlib.loose_files(files)` scan was not
    # prefix-scoped; it could return another day's sample (the envelope-reprobe anti-pattern).
    out = []
    for name, data in binlib.prefix_scoped(files, 1):
        if data[:4] == ELF_MAGIC and ELFFile(io.BytesIO(data)).get_section_by_name(".huntress") is not None:
            out.append((name, data))
    return out


def answers(questions, files, ctx):
    samples = pick_sample(files)
    if not samples:
        return {}
    fields = analyze(samples[0][1])
    out = {}
    for q in questions:
        field = re.sub(r"^d0*1_", "", q["qid"])
        got = binlib.sha256_field(field, samples)
        out[q["qid"]] = got if got is not None else fields.get(field)
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for path in sys.argv[1:]:
        with open(path, "rb") as fh:
            blob = fh.read()
        print(path)
        print(f"  artifact_sha256_1 = {binlib.sha256_field('artifact_sha256_1', [(path, blob)])}")
        for k, v in analyze(blob).items():
            print(f"  {k} = {v}")
