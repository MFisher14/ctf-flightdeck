#!/usr/bin/env python3
"""Offline tests for row 8 of docs/retro/reference-technique-buildlist.md: PLT/GOT/import-address +
generic symbol-address resolution in solvers/toolkits/pwn.py. No Game Master request, no token, no
network: one minimal but valid ELF (symbol table + .rela.plt + .plt) is built in memory, and the
never-wrong boundary is proven on hand-built reports.

  .venv/bin/python tests/test_pwn_pltgot.py

Proves the never-wrong class (plain-eligible): a resolved symbol/GOT/PLT address is byte-derived and
offered as a RENDERING candidate pick, never plain before the judge accepts a rendering; an absent
symbol, an ambiguous question (two named symbols) and an ambiguous fact (one symbol, two values) all
resolve to None (the address is never guessed); the flag is always None. One lifecycle test shows the
plain-eligibility: once a rendering is accepted, the fact answers each variant's OWN byte-derived
value plain -- never a stale value.
"""
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_pwn_pltgot_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pytest     # noqa: E402
import labels      # noqa: E402
import pwn as P     # noqa: E402

FAILED = []


def judge_backed() -> bool:
    """True when the loaded labels module replays judge acceptance: labels.judge_ledger() is on
    (the event's judge answers per name). Off, or a labels module without it (the neutral shim),
    means an accepted name is never replayed as a plain answer, so the judge tests cannot pass."""
    ledger = getattr(labels, "judge_ledger", None)
    return callable(ledger) and ledger()


# Judge-acceptance tests (an accepted name replays as plain): marked `judge` and skipped, with the
# reason shown, unless a judge-backed labels module is loaded. They used to be dropped from main().
JUDGE = (pytest.mark.judge, pytest.mark.skipif(
    not judge_backed(), reason="judge-acceptance replay needs a judge-backed labels module "
                               "(labels.judge_ledger() is off or absent)"))


def judge(fn):
    for mark in reversed(JUDGE):
        fn = mark(fn)
    return fn


def run_judge(fn):
    """main()'s call of a judge test: run it, or print why it is skipped (never a silent pass)."""
    if judge_backed():
        fn()
    else:
        print(f"skip {fn.__name__}: {JUDGE[1].kwargs['reason']}")


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


# ---------------------------------------------------------------------------- a real minimal ELF

SHT = {"NULL": 0, "PROGBITS": 1, "SYMTAB": 2, "STRTAB": 3, "RELA": 4, "DYNSYM": 11}
SHF_ALLOC, SHF_EXEC = 0x2, 0x4
STB_GLOBAL, STT_FUNC = 1, 2
R_X86_64_JUMP_SLOT = 7

# Addresses baked into the ELF: the facts the resolver must read back exactly.
MAIN_ADDR, WIN_ADDR = 0x1149, 0x1176
PLT_BASE, PLT_ENT = 0x1020, 16
PUTS_GOT, SYSTEM_GOT = 0x4000, 0x4008
PUTS_PLT, SYSTEM_PLT = PLT_BASE + 1 * PLT_ENT, PLT_BASE + 2 * PLT_ENT   # classic: header + i-th entry


def _sym(st_name, st_info, shndx, value):
    return struct.pack("<IBBHQQ", st_name, st_info, 0, shndx, value, 0)


def _rela(off, sym_idx, rtype):
    return struct.pack("<QQq", off, (sym_idx << 32) | rtype, 0)


def _strtab(names):
    blob, offs = b"\x00", {}
    for n in names:
        offs[n] = len(blob)
        blob += n.encode() + b"\x00"
    return blob, offs


def build_elf(plt_sec=False):
    """A 64-bit LE ET_EXEC with .text, .plt, .dynsym/.dynstr, .rela.plt, .symtab/.strtab. Defined
    symbols main/win (in .symtab), undefined imports puts/system (in .dynsym) patched by two
    JUMP_SLOT relocations in .rela.plt, and a classic .plt sized header + one entry per relocation.
    With plt_sec=True an extra ".plt.sec" section is added: the PLT stub address is then ambiguous
    and must not be resolved."""
    info = STB_GLOBAL << 4 | STT_FUNC
    dynstr, dso = _strtab(["puts", "system"])
    dynsym = _sym(0, 0, 0, 0) + _sym(dso["puts"], info, 0, 0) + _sym(dso["system"], info, 0, 0)
    relaplt = _rela(PUTS_GOT, 1, R_X86_64_JUMP_SLOT) + _rela(SYSTEM_GOT, 2, R_X86_64_JUMP_SLOT)
    strtab, so = _strtab(["main", "win"])
    symtab = _sym(0, 0, 0, 0) + _sym(so["main"], info, 1, MAIN_ADDR) + _sym(so["win"], info, 1, WIN_ADDR)
    text = bytes(16)
    plt = bytes(PLT_ENT * 3)                       # resolver header + two stubs

    # (name, sh_type, flags, addr, link, info, entsize, data)
    secs = [
        ("", "NULL", 0, 0, 0, 0, 0, b""),
        (".text", "PROGBITS", SHF_ALLOC | SHF_EXEC, 0x1000, 0, 0, 0, text),
        (".plt", "PROGBITS", SHF_ALLOC | SHF_EXEC, PLT_BASE, 0, 0, PLT_ENT, plt),
        (".dynsym", "DYNSYM", SHF_ALLOC, 0x400, 4, 1, 24, dynsym),
        (".dynstr", "STRTAB", SHF_ALLOC, 0x480, 0, 0, 0, dynstr),
        (".rela.plt", "RELA", SHF_ALLOC, 0x500, 3, 2, 24, relaplt),
        (".symtab", "SYMTAB", 0, 0, 7, 1, 24, symtab),
        (".strtab", "STRTAB", 0, 0, 0, 0, 0, strtab),
        (".shstrtab", "STRTAB", 0, 0, 0, 0, 0, None),
    ]
    if plt_sec:
        # Added as the second-to-last section so the existing sh_link/sh_info indices stay valid;
        # .shstrtab must remain last (e_shstrndx = shnum - 1).
        secs.insert(len(secs) - 1,
                    (".plt.sec", "PROGBITS", SHF_ALLOC | SHF_EXEC, 0x1060, 0, 0, PLT_ENT, bytes(PLT_ENT * 2)))
    shstr, nmoff = _strtab([s[0] for s in secs if s[0]])
    nmoff[""] = 0
    secs[-1] = (".shstrtab", "STRTAB", 0, 0, 0, 0, 0, shstr)

    ehsize, shentsize, shnum = 64, 64, len(secs)
    # Lay the section data out after the header; the section header table comes last.
    blobs, offsets, cur = [], [], ehsize
    for (_nm, _t, _fl, _ad, _ln, _in, _es, data) in secs:
        data = data or b""
        if data:
            offsets.append(cur)
            blobs.append(data)
            cur += len(data)
        else:
            offsets.append(0)
    shoff = cur
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 0, shoff, 0,
                               ehsize, 0, 0, shentsize, shnum, shnum - 1)
    shtab = b""
    for i, (nm, t, fl, ad, ln, inf, es, data) in enumerate(secs):
        shtab += struct.pack("<IIQQQQIIQQ", nmoff[nm], SHT[t], fl, ad, offsets[i],
                             len(data or b""), ln, inf, 1, es)
    return ehdr + b"".join(blobs) + shtab


# ---------------------------------------------------------------------------- end-to-end on the ELF

def _ans(elf, question, aid="a"):
    return P.solve_set([{"id": aid, "question": question, "answer_format": {"kind": "exact_text"}}],
                       {"chall": elf}, {"set": 0, "attempt": {}})[aid]


def test_read_elf_resolution_maps():
    elf = build_elf()
    info = P.read_elf(elf)
    check("read_elf parses the crafted ELF (pyelftools present)", info is not None and info["pyelftools"], info)
    if not info or not info["pyelftools"]:
        return
    check("defined symbols resolve to their st_value (main, win)",
          info["sym_values"].get("main") == {MAIN_ADDR} and info["sym_values"].get("win") == {WIN_ADDR},
          info["sym_values"])
    check("undefined imports are NOT resolvable symbol addresses (puts/system have no st_value)",
          "puts" not in info["sym_values"] and "system" not in info["sym_values"], info["sym_values"])
    check("GOT entries are the relocation r_offsets (the import addresses)",
          info["got_offsets"].get("puts") == {PUTS_GOT} and info["got_offsets"].get("system") == {SYSTEM_GOT},
          info["got_offsets"])
    check("PLT stubs resolve in the classic layout (header + .rela.plt order)",
          info["plt_map"].get("puts") == {PUTS_PLT} and info["plt_map"].get("system") == {SYSTEM_PLT},
          info["plt_map"])
    # Ambiguous layout: a ".plt.sec" means the stub address is not a single classic-layout fact.
    amb = P.read_elf(build_elf(plt_sec=True))
    check("a .plt.sec present -> PLT stubs are NOT resolved (ambiguous, never guessed), GOT still is",
          amb["plt_map"] == {} and amb["got_offsets"].get("puts") == {PUTS_GOT}, amb["plt_map"])


def test_end_to_end_candidates():
    elf = build_elf()
    sym = _ans(elf, "At what address is the `main` function located?")
    check("symbol address is a candidate pick carrying the byte-derived value, never plain",
          labels.is_candidate(sym) and not _plain(sym)
          and any(v == hex(MAIN_ADDR) for _n, v in labels.parse(sym).options)
          and labels.parse(sym).key.startswith("pwn.sym_addr/"), sym)
    got = _ans(elf, "What is the GOT entry (import address) for puts?")
    check("GOT entry is a candidate pick under pwn.got carrying the relocation r_offset",
          labels.is_candidate(got) and labels.parse(got).key.startswith("pwn.got/")
          and any(v == hex(PUTS_GOT) for _n, v in labels.parse(got).options), got)
    plt = _ans(elf, "What is the address of the system PLT stub?")
    check("PLT stub is a candidate pick under pwn.plt carrying the computed stub address",
          labels.is_candidate(plt) and labels.parse(plt).key.startswith("pwn.plt/")
          and any(v == hex(SYSTEM_PLT) for _n, v in labels.parse(plt).options), plt)


def test_never_guess_boundary():
    """The core never-wrong boundary, on hand-built reports so each case is exact."""
    # Symbol names chosen to avoid the question-routing keywords (win/entry/got/plt/...), so each
    # case exercises the generic symbol-address path and nothing else.
    info = {"class": 64,
            "sym_values": {"main": {MAIN_ADDR}, "helper": {WIN_ADDR}, "ambig": {0x1, 0x2}},
            "got_offsets": {"puts": {PUTS_GOT}},
            "plt_map": {"puts": {PUTS_PLT}},
            "protections": {}}

    def ans(question, aid="a"):
        return P._answer_one({"id": aid, "question": question,
                              "answer_format": {"kind": "exact_text"}}, info)

    # (1) a symbol the binary does not carry -> None (never guessed).
    check("address of an ABSENT symbol -> None", ans("What is the address of the strcmp function?") is None)
    check("GOT entry of a symbol with no relocation -> None", ans("GOT entry address for malloc?") is None)
    check("PLT stub of a symbol with no PLT entry -> None", ans("What is the address of the printf PLT stub?") is None)
    # (2) a question naming TWO present symbols -> None (which one is not guessed).
    check("address question naming two present symbols (main, helper) -> None",
          ans("What is the address of main, and of helper?") is None)
    # (3) a present symbol whose fact is AMBIGUOUS (two values) -> None (never guessed).
    check("symbol defined at two different addresses -> None", ans("At what address is ambig located?") is None)
    # (4) a question naming exactly one present symbol -> resolved candidate (unsure), never plain.
    one = ans("At what address is helper located?")
    check("exactly one present symbol -> candidate pick, never plain",
          labels.is_candidate(one) and not _plain(one)
          and any(v == hex(WIN_ADDR) for _n, v in labels.parse(one).options), one)
    # (5) the flag and an unrelated question are always None.
    check("the flag is always None", ans("What is the flag at the win address?") is None)
    check("empty symbol maps never raise (header-only ELF) -> None",
          P._answer_one({"id": "a", "question": "address of main?", "answer_format": {}},
                        {"class": 64, "sym_values": {}, "got_offsets": {}, "plt_map": {},
                         "protections": {}}) is None)


@judge
def test_plain_eligibility_lifecycle():
    """plain-eligible: never plain before a rendering is judged; once the judge accepts a rendering
    name, the fact answers each variant's OWN byte-derived value plain -- never a stale value."""
    a = {"class": 64, "sym_values": {"target": {0x401176}}, "got_offsets": {}, "plt_map": {}, "protections": {}}
    b = {"class": 64, "sym_values": {"target": {0x55aabbcc}}, "got_offsets": {}, "plt_map": {}, "protections": {}}

    def ans(info):
        return P._answer_one({"id": "a", "question": "At what address is target located?",
                              "answer_format": {"kind": "exact_text"}}, info)

    before = ans(a)
    check("before any verdict the address is unsure (a candidate pick), never plain",
          labels.is_candidate(before) and not _plain(before), before)
    key = labels.parse(before).key
    labels.learn(key, "hex", "accepted", scope="key")          # the judge accepts the hex rendering
    after_a = ans(a)
    check("after 'hex' is accepted, variant A answers its own address plain in hex",
          after_a == hex(0x401176), after_a)
    after_b = ans(b)
    check("variant B (a different binary) answers ITS OWN byte-derived address plain, not A's stale value",
          after_b == hex(0x55aabbcc), after_b)


def _plain(v):
    return isinstance(v, str) and not labels.is_unsure(v)


def main():
    import shutil
    try:
        test_read_elf_resolution_maps()
        test_end_to_end_candidates()
        test_never_guess_boundary()
        run_judge(test_plain_eligibility_lifecycle)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
