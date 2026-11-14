"""B-026: decompile + invert byte-compare / mixer / per-char checks (z3/angr).

Most tests run with no external tool: the three z3 inverters (per-byte index-dependent transforms,
per-position uniqueness search, fixed-width invertible mixers) are driven by synthetic transforms
built in the test, and every "it inverts X" assertion is a round-trip -- apply the forward transform,
invert it, and require the original back -- so the test fails when the inverter is wrong.  Two tests
assemble a straight-line x86-64 check from source (``clang -target x86_64-linux-gnu``) and lift it
end to end; they are marked ``needs_tool("clang")`` so they report NOT RUN where clang is absent,
never silently green.  Nothing here executes a challenge binary: the fixtures are our own synthetic
source, and verification is a z3 proof or a forward re-apply.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "binary"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "toolkits"))

import invert_checks as ic             # noqa: E402  (flat import, the engine sys.path)
import symbolic                        # noqa: E402
import z3                              # noqa: E402
from ctf import event                  # noqa: E402
from ctf.engines import manifest as _manifest   # noqa: E402
from ctf.result import SolverResult    # noqa: E402

CSCTF = event.load("csctf")


# ============================================================ per-byte index-dependent transform

def test_apply_byte_ops_matches_a_hand_computation():
    # ((s ^ 0x5d) + 7*i + 0x0b) & 0xff  at i = 3, s = ord('L')
    ops = [("xor", 0x5D), ("add", {"i_mul": 7, "i_add": 0x0B})]
    expected = (((ord("L") ^ 0x5D) + 7 * 3 + 0x0B) & 0xFF)
    assert ic.apply_byte_ops(ord("L"), 3, ops) == expected


def test_invert_per_byte_recovers_an_affine_index_dependent_check():
    # The frankensteins-password-generator check: ((s[i]^0x5d)+7*i+0x0b)&0xff == T[i].
    password = b"BOLTATMIDNIGHT"
    ops = [("xor", 0x5D), ("add", {"i_mul": 7, "i_add": 0x0B})]
    targets = bytes(ic.apply_byte_ops(c, i, ops) for i, c in enumerate(password))
    sol = ic.invert_per_byte(targets, ops, charset=(0x20, 0x7E))
    assert sol.is_unique
    assert sol.plain() == password
    assert sol.candidate_values() == []


def test_invert_per_byte_handles_rotate_and_per_index_table():
    # rol8(s[i], (1+3i)&7) added to a repeating key[i&7]: the lock-box per-byte shape (stateless part).
    key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    ops = [("rol", {"i_mul": 3, "i_add": 1, "mask": 7}),
           ("add", {"table": key, "mask": 7})]
    secret = bytes((0x41 + i) for i in range(10))     # arbitrary input
    targets = bytes(ic.apply_byte_ops(c, i, ops) for i, c in enumerate(secret))
    sol = ic.invert_per_byte(targets, ops)
    assert sol.is_unique
    assert sol.plain() == secret


def test_invert_per_byte_multiple_preimages_are_candidates_never_plain():
    # mul by 2 is NOT a bijection mod 256: an even target has exactly two preimages (x and x+128).
    sol = ic.invert_per_byte([0x10], [("mul", 2)])
    assert sol.status == symbolic.MULTIPLE
    assert sol.plain() is None
    # width 8 -> each candidate decodes to a 1-byte value (0x08 and 0x88, since 2*x == 0x10 mod 256).
    assert sorted(sol.candidate_values()) == [b"\x08", b"\x88"]


def test_invert_per_byte_unsat_target_returns_none():
    # mul by 2 can never produce an odd byte -> contradiction -> None (never a wrong answer).
    sol = ic.invert_per_byte([0x11], [("mul", 2)])
    assert sol.status == symbolic.UNSAT
    assert sol.plain() is None


def test_invert_per_byte_wide_cell_width():
    # 16-bit cells, add then xor, recovered uniquely (bijection), width != 8 -> model dict, not bytes.
    ops = [("add", 0x1234), ("xor", 0xBEEF)]
    vals = [0x0001, 0xABCD, 0xFFFF]
    targets = [ic.apply_byte_ops(v, i, ops, width=16) for i, v in enumerate(vals)]
    sol = ic.invert_per_byte(targets, ops, width=16)
    assert sol.is_unique
    assert sol.plain() == {"in0": 0x0001, "in1": 0xABCD, "in2": 0xFFFF}


# ---- operand resolution + validation

def test_coeff_resolves_every_operand_form():
    assert ic._coeff(0x5D, 9) == 0x5D                                  # constant
    assert ic._coeff([10, 20, 30], 2) == 30                           # full table
    assert ic._coeff({"i_mul": 7, "i_add": 0x0B}, 3) == 7 * 3 + 0x0B  # index expr
    assert ic._coeff({"i_mul": 3, "i_add": 1, "mask": 7}, 5) == ((3 * 5 + 1) & 7)
    assert ic._coeff({"table": [1, 2, 3, 4], "mask": 3}, 6) == [1, 2, 3, 4][6 & 3]


def test_coeff_rejects_bad_operands():
    with pytest.raises(ic.InvertError):
        ic._coeff(True, 0)                       # a bool is not an int operand
    with pytest.raises(ic.InvertError):
        ic._coeff([1, 2], 5)                     # table has no entry for the index
    with pytest.raises(ic.InvertError):
        ic._coeff({"i_mul": 1, "bogus": 2}, 0)   # unknown key


def test_invert_per_byte_validates_its_inputs():
    with pytest.raises(ic.InvertError):
        ic.invert_per_byte(b"AB", [])                       # no ops
    with pytest.raises(ic.InvertError):
        ic.invert_per_byte(b"AB", [("nope", 1)])            # unknown op
    with pytest.raises(ic.InvertError):
        ic.invert_per_byte([256], [("xor", 1)])             # target out of byte range
    with pytest.raises(ic.InvertError):
        ic.invert_per_byte("AB", [("xor", 1)])              # targets must be bytes/ints
    with pytest.raises(ic.InvertError):
        ic.invert_per_byte(b"A", [("xor", 1)], width=0)     # bad width


# ============================================================ fixed-width invertible mixer

def test_inv_rshift_xor_round_trips():
    for width in (16, 32, 64):
        for shift in (1, 5, width // 3, width - 1):
            for x in (0, 1, 0xA5A5A5A5A5A5A5A5 & ((1 << width) - 1), (1 << width) - 1):
                y = x ^ (x >> shift)
                assert ic.inv_rshift_xor(y, shift, width) == x, (width, shift, x)


def test_inv_lshift_xor_round_trips():
    for width in (16, 32, 64):
        for shift in (1, 7, width - 1):
            mask = (1 << width) - 1
            for x in (0, 1, 0x0123456789ABCDEF & mask, mask):
                y = (x ^ (x << shift)) & mask
                assert ic.inv_lshift_xor(y, shift, width) == x, (width, shift, x)


def test_invert_mixer_recovers_a_murmur_fmix64_with_custom_multipliers():
    # A custom-multiplier fmix64: arbitrary odd 64-bit multipliers (not murmur's), no signature.
    c1, c2 = 0x6A09E667F3BCC909, 0xBB67AE8584CAA73B
    mix = [("xorshift_right", 33), ("mul", c1), ("xorshift_right", 33),
           ("mul", c2), ("xorshift_right", 33)]
    for x in (0, 1, 0x0123456789ABCDEF, 0xDEADBEEFCAFEF00D, (1 << 64) - 1):
        y = ic.apply_mixer(x, mix, width=64)
        assert ic.invert_mixer(y, mix, width=64) == x, hex(x)


def test_invert_mixer_handles_rotate_add_xor_and_multiple_widths():
    mix = [("rotl", 13), ("xor", 0x55AA), ("mul", 0x9E3779B1), ("add", 0x1234), ("xorshift_left", 7)]
    for width in (16, 32):
        mask = (1 << width) - 1
        for x in (0, 7, 0xABCD1234 & mask, mask):
            y = ic.apply_mixer(x, mix, width=width)
            assert ic.invert_mixer(y, mix, width=width) == x, (width, hex(x))


def test_invert_mixer_rejects_a_non_invertible_even_multiplier():
    with pytest.raises(ic.InvertError):
        ic.invert_mixer(0x1234, [("mul", 2)], width=16)
    with pytest.raises(ic.InvertError):
        ic.apply_mixer(0x1234, [("mul", 4)], width=16)


def test_modinv_pow2_is_a_true_inverse():
    for width in (8, 32, 64):
        mod = 1 << width
        for m in (1, 3, 0x9E3779B1, (1 << width) - 1):
            inv = ic._modinv_pow2(m, width)
            assert (m * inv) % mod == 1


# ============================================================ per-position uniqueness search

def test_invert_positions_assembles_a_uniquely_pinned_key():
    # Each position i is pinned by its own equation s[i] + (3i+1) == (target[i] + 3i + 1) & 0xff.
    target = b"secret!"

    def check(i, x):
        return (x + z3.BitVecVal(i * 3 + 1, 8)) == z3.BitVecVal((target[i] + i * 3 + 1) & 0xFF, 8)

    sol = ic.invert_positions(len(target), check)
    assert sol.is_unique
    assert sol.plain() == target


def test_invert_positions_reports_an_ambiguous_position_and_refuses_plain():
    # Position 1 allows two bytes (x*2 == 0 mod 256): not unique -> no plain, position named.
    def check(i, x):
        if i == 1:
            return x * z3.BitVecVal(2, 8) == z3.BitVecVal(0, 8)     # x in {0, 128}
        return x == z3.BitVecVal(0x41, 8)

    sol = ic.invert_positions(3, check)
    assert sol.plain() is None
    assert sol.status == symbolic.MULTIPLE
    assert "pos 1" in sol.detail


def test_invert_positions_underconstrained_position_is_the_worst_status():
    def check(i, x):
        if i == 0:
            return x == z3.BitVecVal(0x41, 8)
        return z3.ULT(x, 200)                     # many solutions -> underconstrained

    sol = ic.invert_positions(2, check)
    assert sol.plain() is None
    assert sol.status == symbolic.UNDERCONSTRAINED


def test_invert_positions_validates_inputs():
    with pytest.raises(ic.InvertError):
        ic.invert_positions(0, lambda i, x: x == 0)
    with pytest.raises(ic.InvertError):
        ic.invert_positions(4, "not callable")


# ============================================================ ELF function ranking (no tool: capstone)

def _info_with(code_sections, functions, entry=0x1000):
    return {"arch": "amd64", "class": 64, "exec_sections": code_sections,
            "functions": functions, "entry": entry}


def test_find_check_candidates_ranks_comparison_heavy_functions():
    # fa: two `cmp eax, imm32` (0x3d ...) -> comparison immediates; fb: just `ret` -> no immediates.
    fa = b"\x3d\x37\x13\x00\x00\x3d\x05\x00\x00\x00\xc3" + b"\x90" * 5    # 16 bytes
    fb = b"\xc3" + b"\x90" * 7
    code = fa + fb
    info = _info_with([(".text", 0x1000, code)],
                      [("fa", 0x1000), ("fb", 0x1000 + len(fa))])
    cands = ic.find_check_candidates(info)
    names = [n for n, _a in cands]
    assert "fa" in names                       # scored (has cmp immediates)
    assert "fb" not in names                   # score 0 -> excluded
    assert ("entry", 0x1000) not in cands       # entry equals fa's addr, not duplicated
    # a distinct entry address is always appended as a candidate
    info2 = _info_with([(".text", 0x1000, code)], [("fa", 0x1000)], entry=0x2000)
    assert ("entry", 0x2000) in ic.find_check_candidates(info2)


def test_func_extents_runs_each_function_to_the_next_start():
    info = _info_with([(".text", 0x1000, b"\x90" * 0x80)],
                      [("a", 0x1000), ("b", 0x1020), ("c", 0x1050)])
    ext = ic._func_extents(info)
    assert ext[0x1000] == 0x20                 # a -> b
    assert ext[0x1020] == 0x30                 # b -> c
    assert ext[0x1050] == 0x30                 # c -> section end (0x1080)


def test_invert_elf_straightline_names_why_non_elf_bytes_are_skipped():
    with pytest.raises(ic.ElfSkipped, match="not a parseable ELF"):
        ic.invert_elf_straightline(b"not an elf at all")


# ============================================================ engine entry

def test_solve_reports_none_without_an_elf(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "readme.txt").write_text("no binary here")
    res = ic.solve(tmp_path, CSCTF)
    assert isinstance(res, SolverResult)
    assert res.status == "none"
    assert "no ELF" in res.notes


# ============================================================ manifest

def test_manifest_is_valid_and_entry_resolves():
    root = Path(__file__).resolve().parents[1]
    m = _manifest.load(root / "solvers" / "binary" / "invert_checks.manifest.toml")
    assert m.id == "binary.invert_checks"
    assert m.entry.target_file(root).name == "invert_checks.py"
    assert "analysis" in m.capabilities
    assert any("reverse" in (r.category or []) for r in m.routes)


def test_engine_is_in_the_generated_route_table():
    root = Path(__file__).resolve().parents[1]
    table = (root / "ctf" / "engines" / "route_table.jsonl").read_text()
    assert '"binary.invert_checks"' in table


# ============================================================ end-to-end lift (needs clang)

_BRANCHLESS_CHECK = """\
    .text
    .globl _pad
    .type _pad,@function
_pad:
    ret

    .globl check
    .type check,@function
check:
    movzbl (%rdi), %eax
    xorb $0x73, %al
    movzbl 1(%rdi), %edx
    xorb $0x31, %dl
    orb %dl, %al
    movzbl 2(%rdi), %edx
    xorb $0x6d, %dl
    orb %dl, %al
    movzbl 3(%rdi), %edx
    xorb $0x21, %dl
    orb %dl, %al
    movzbl %al, %eax
    ret
"""


def _assemble_x86_64(src: str, tmp_path: Path) -> bytes:
    """Assemble our own source into an x86-64 ELF object (never a challenge binary).  Skips with a
    named reason if clang cannot emit an x86-64 Linux ELF on this host (clang is present but the
    target backend is not usable)."""
    s = tmp_path / "chk.s"
    s.write_text(src)
    o = tmp_path / "chk.o"
    try:
        subprocess.run(["clang", "-target", "x86_64-linux-gnu", "-c", str(s), "-o", str(o)],
                       check=True, capture_output=True, timeout=60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        pytest.skip(f"clang cannot emit an x86-64 Linux ELF here: {e}")
    data = o.read_bytes()
    assert data[:4] == b"\x7fELF" and data[18:20] == b"\x3e\x00", "fixture is not an x86-64 ELF"
    return data


@pytest.mark.needs_tool("clang")
def test_invert_elf_straightline_recovers_a_branchless_byte_compare(tmp_path):
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    rows = ic.invert_elf_straightline(data, lengths=[4])
    assert any(r.value == b"s1m!" for r in rows), [r.as_text() for r in rows]
    r = next(r for r in rows if r.value == b"s1m!")
    assert r.func == "check" and r.length == 4


@pytest.mark.needs_tool("clang")
def test_solve_recovers_input_from_an_elf_in_the_handout(tmp_path):
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    (chal / "files" / "keycheck").write_bytes(data)
    res = ic.solve(chal, CSCTF)
    assert res.status == "unsure"           # recovered a key, not a flag
    assert "s1m!" in res.notes
    assert any(ev.kind == "recovered-input" for ev in res.evidence)


# ============================================================ round-1 verification fixes

def _branchless_asm(secret: bytes, name: str = "check") -> str:
    """A branchless straight-line check `return OR_i (s[i] ^ secret[i])` (0 == accepted), after a
    `_pad` function so `name` does not start the section."""
    lines = ["    .text", "    .globl _pad", "    .type _pad,@function", "_pad:", "    ret", "",
             f"    .globl {name}", f"    .type {name},@function", f"{name}:",
             "    movzbl (%rdi), %eax", f"    xorb ${secret[0]:#x}, %al"]
    for i, c in enumerate(secret[1:], start=1):
        lines += [f"    movzbl {i}(%rdi), %edx", f"    xorb ${c:#x}, %dl", "    orb %dl, %al"]
    lines += ["    movzbl %al, %eax", "    ret", ""]
    return "\n".join(lines)


# A check that jumps to a SEPARATE fail function placed right after it: only per-function extent
# slicing keeps `fail` out of check's lifted region (otherwise the jne is an in-region jump -> PARTIAL).
_JNE_TO_FAIL_CHECK = """\
    .text
    .globl _pad
    .type _pad,@function
_pad:
    ret

    .globl check
    .type check,@function
check:
    cmpb $0x6b, (%rdi)
    jne fail
    cmpb $0x33, 1(%rdi)
    jne fail
    cmpb $0x79, 2(%rdi)
    jne fail
    cmpb $0x5a, 3(%rdi)
    jne fail
    movl $1, %eax
    ret

    .type fail,@function
    # `fail` is a LOCAL function symbol, so the assembler resolves the jne itself (a .globl target
    # in an object file would be left to a relocation with a zero displacement).
fail:
    xorl %eax, %eax
    ret
"""


def _write_elf_magic_junk(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + b"\xff" * 12)      # ELF magic, not a parseable ELF


def _aarch64_elf() -> bytes:
    import struct
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, 0x400000, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    return hdr + b"\0" * 64


# ---- inverter boundaries

def test_invert_mixer_forward_reapply_guard_rejects_a_wrong_inverse(monkeypatch):
    # Break one inverse step: the forward re-apply must catch it (never return an unverified input).
    mix = [("xorshift_right", 17), ("mul", 0x9E3779B97F4A7C15)]
    y = ic.apply_mixer(0x0123456789ABCDEF, mix, width=64)
    monkeypatch.setattr(ic, "inv_rshift_xor", lambda v, s, w: (v + 1) & ((1 << w) - 1))
    with pytest.raises(ic.InvertError, match="does not reproduce"):
        ic.invert_mixer(y, mix, width=64)


def test_invert_per_byte_charset_alone_pins_a_non_bijective_transform():
    # mul 2 mod 256: each target has preimages x and x+128.  Only the printable charset makes it unique.
    targets = [ic.apply_byte_ops(c, i, [("mul", 2)]) for i, c in enumerate(b"HI")]
    loose = ic.invert_per_byte(targets, [("mul", 2)])
    assert loose.status == symbolic.MULTIPLE and loose.plain() is None
    pinned = ic.invert_per_byte(targets, [("mul", 2)], charset=(0x20, 0x7E))
    assert pinned.is_unique
    assert pinned.plain() == b"HI"


def test_find_check_candidates_named_function_outranks_a_comparison_heavy_one():
    fa = b"\x3d\x37\x13\x00\x00\x3d\x05\x00\x00\x00\xc3" + b"\x90" * 5    # two cmp imm32
    fv = b"\xc3" + b"\x90" * 7                                            # just `ret`, no immediates
    info = _info_with([(".text", 0x1000, fa + fv)],
                      [("fa", 0x1000), ("verify_key", 0x1000 + len(fa))])
    cands = ic.find_check_candidates(info)
    assert cands[0] == ("verify_key", 0x1000 + len(fa))     # the name bonus ranks it first
    assert ("fa", 0x1000) in cands


def test_invert_elf_straightline_rejects_bad_lengths():
    with pytest.raises(ic.InvertError, match="input length"):
        ic.invert_elf_straightline(b"\x7fELF", lengths=[0])
    with pytest.raises(ic.InvertError, match="input length"):
        ic.invert_elf_straightline(b"\x7fELF", lengths=[ic.MAX_LEN + 1])


def test_invert_elf_straightline_names_an_unsupported_architecture():
    with pytest.raises(ic.ElfSkipped, match="aarch64"):
        ic.invert_elf_straightline(_aarch64_elf(), lengths=[4])


def test_invert_elf_straightline_stats_an_oversized_file_before_reading_it(tmp_path, monkeypatch):
    f = tmp_path / "big.elf"
    f.write_bytes(_aarch64_elf())
    monkeypatch.setattr(ic, "MAX_ELF_BYTES", 16)

    def no_read(self):
        raise AssertionError("an oversized file must not be read")

    monkeypatch.setattr(Path, "read_bytes", no_read)
    with pytest.raises(ic.ElfSkipped, match="larger than 16 bytes"):
        ic.invert_elf_straightline(f, lengths=[4])


def test_pwn_toolkit_missing_fails_loudly(tmp_path, monkeypatch):
    monkeypatch.setattr(ic, "TOOLKITS", tmp_path)          # no pwn.py here
    monkeypatch.setattr(ic, "_PWN_TOOLKIT", [])
    with pytest.raises(RuntimeError, match="pwn.py"):
        ic._read_elf(_aarch64_elf())


def test_read_elf_is_not_fooled_by_a_shadowing_pwn_module(monkeypatch):
    # pwntools (`from pwn import *`) binds sys.modules['pwn'] without read_elf; the toolkit is loaded by
    # path, so the static reader still works.
    import types
    monkeypatch.setitem(sys.modules, "pwn", types.ModuleType("pwn"))
    monkeypatch.setattr(ic, "_PWN_TOOLKIT", [])
    info = ic._read_elf(_aarch64_elf())
    assert info is not None and info["arch"] == "aarch64"


# ---- handout walk

def test_elf_files_skips_recon_unpacked_and_symlinks(tmp_path):
    chal = tmp_path / "chal"
    _write_elf_magic_junk(chal / "files" / "real")
    _write_elf_magic_junk(chal / "recon" / "decompile" / "copy")
    _write_elf_magic_junk(chal / "unpacked" / "inner")
    outside = tmp_path / "outside_elf"
    _write_elf_magic_junk(outside)
    (chal / "files" / "link").symlink_to(outside)
    files, over = ic._handout_files(chal)
    got = [(p.relative_to(chal).as_posix(), kind) for p, kind in files]
    assert got == [("files/real", "elf")] and over == 0


# ---- engine entry: every non-success path names its reason

def test_solve_is_blocked_naming_a_missing_z3(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")

    def no_z3():
        raise RuntimeError("symbolic.py needs z3")

    monkeypatch.setattr(ic.symbolic, "_require_z3", no_z3)
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "needs z3" in res.notes


def test_solve_names_an_inversion_error_and_claims_no_recovery(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    (tmp_path / "recon" / "decompile").mkdir(parents=True)      # decompile evidence present

    def boom(*_a, **_k):
        raise ValueError("lifter exploded")

    monkeypatch.setattr(ic, "invert_elf_straightline", boom)
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "unsure"                    # not 'none': the sweep did not complete
    assert "lifter exploded" in res.notes and "files/bin" in res.notes
    assert "recovered accepted input" not in res.notes
    assert not any(ev.kind == "recovered-input" for ev in res.evidence)
    assert any(ev.kind == "decompile" for ev in res.evidence)


def test_solve_is_blocked_when_no_elf_could_be_analysed(tmp_path):
    _write_elf_magic_junk(tmp_path / "files" / "junk")
    (tmp_path / "files" / "arm").write_bytes(_aarch64_elf())
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "files/junk: not a parseable ELF" in res.notes
    assert "files/arm: architecture 'aarch64'" in res.notes


def test_solve_reports_an_exhausted_time_budget(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "arm").write_bytes(_aarch64_elf())
    res = ic.solve(tmp_path, CSCTF, budget_s=0)
    assert res.status == "unsure"
    assert "time budget of 0 s used up" in res.notes


# ---- end to end (needs clang)

@pytest.mark.needs_tool("clang")
def test_solve_reports_a_candidate_when_the_accepted_input_is_a_flag(tmp_path):
    data = _assemble_x86_64(_branchless_asm(b"CSCTF{ab1}"), tmp_path)
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    (chal / "files" / "keycheck").write_bytes(data)
    res = ic.solve(chal, CSCTF, lengths=[4, 10])
    assert res.status == "candidate"
    assert res.flags == ("CSCTF{ab1}",)
    assert any(ev.kind == "recovered-input" and "CSCTF{ab1}" in ev.detail for ev in res.evidence)


@pytest.mark.needs_tool("clang")
def test_jne_to_a_separate_fail_function_is_lifted_by_extent_slicing(tmp_path):
    data = _assemble_x86_64(_JNE_TO_FAIL_CHECK, tmp_path)
    rows = ic.invert_elf_straightline(data, lengths=[4], funcs=["check"], success_return="nonzero")
    assert [r.value for r in rows] == [b"k3yZ"]


@pytest.mark.needs_tool("clang")
def test_duplicate_recoveries_of_one_function_collapse(tmp_path):
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    rows = ic.invert_elf_straightline(data, lengths=[4], funcs=["check", "check"],
                                      success_return=("zero", "zero"))
    assert [r.value for r in rows] == [b"s1m!"]


@pytest.mark.needs_tool("clang")
def test_invert_elf_straightline_names_an_undefined_function(tmp_path):
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    with pytest.raises(ic.InvertError, match="nope"):
        ic.invert_elf_straightline(data, lengths=[4], funcs=["check", "nope"])


@pytest.mark.needs_tool("clang")
def test_a_passed_deadline_stops_the_sweep_and_says_so(tmp_path):
    import time
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    rows = ic.invert_elf_straightline(data, lengths=[4], deadline=time.monotonic() - 1)
    assert list(rows) == [] and rows.budget_exhausted is True
    live = ic.invert_elf_straightline(data, lengths=[4], deadline=time.monotonic() + 600)
    assert live.budget_exhausted is False and any(r.value == b"s1m!" for r in live)


@pytest.mark.needs_tool("clang")
def test_shadowing_pwn_module_does_not_hide_a_recoverable_check(tmp_path, monkeypatch):
    import types
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    monkeypatch.setitem(sys.modules, "pwn", types.ModuleType("pwn"))
    monkeypatch.setattr(ic, "_PWN_TOOLKIT", [])
    rows = ic.invert_elf_straightline(data, lengths=[4])
    assert any(r.value == b"s1m!" for r in rows)


# ============================================================ round-2 verification fixes

import struct  # noqa: E402

M64 = (1 << 64) - 1


def _x86_64_header_elf() -> bytes:
    """An x86-64 ELF header with no sections: parseable as amd64, nothing for pyelftools to read."""
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    hdr += struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    return hdr + b"\0" * 64


# ---- missing capstone / pyelftools / JVM decoder: blocked or a named error, never a silent 'none'

@pytest.mark.parametrize("module, package", [("capstone", "capstone"), ("elftools", "pyelftools")])
def test_solve_is_blocked_naming_a_missing_static_dependency(tmp_path, monkeypatch, module, package):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    monkeypatch.setitem(sys.modules, module, None)          # the import now raises ImportError
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert f"needs {package}" in res.notes


def test_invert_elf_straightline_names_a_missing_capstone(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)
    with pytest.raises(RuntimeError, match="needs capstone"):
        ic.invert_elf_straightline(_x86_64_header_elf(), lengths=[4])


def test_solve_is_blocked_naming_a_missing_jvm_decoder(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    monkeypatch.setattr(ic, "_LIFTERS", [])
    monkeypatch.setattr(ic, "HERE", tmp_path / "nowhere")
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "JVM decoder bytecode_lifters.py" in res.notes


def test_an_elf_whose_tables_pyelftools_cannot_read_is_a_named_skip(monkeypatch):
    # read_elf falls back to header facts when pyelftools cannot parse: that must be a skip, not "no
    # functions, nothing to invert".
    monkeypatch.setattr(ic._pwn_toolkit(), "_with_pyelftools", lambda data, h: None)
    with pytest.raises(ic.ElfSkipped, match="pyelftools"):
        ic.invert_elf_straightline(_x86_64_header_elf(), lengths=[4])


def test_the_bytes_input_is_size_capped_too(monkeypatch):
    monkeypatch.setattr(ic, "MAX_ELF_BYTES", 32)
    with pytest.raises(ic.ElfSkipped, match="larger than 32 bytes"):
        ic.invert_elf_straightline(_x86_64_header_elf(), lengths=[4])


@pytest.mark.needs_tool("clang")
def test_lift_without_capstone_raises_instead_of_reading_as_nothing(tmp_path, monkeypatch):
    data = _assemble_x86_64(_BRANCHLESS_CHECK, tmp_path)
    monkeypatch.setattr(ic, "_require_static_deps", lambda: None)   # get past the preflight
    monkeypatch.setitem(sys.modules, "capstone", None)
    with pytest.raises(RuntimeError, match="capstone"):            # the mixer pass's disassembly
        ic.invert_elf_straightline(data, lengths=[4], funcs=["check"])
    monkeypatch.setattr(ic, "_mixer_row", lambda *a, **k: None)
    monkeypatch.setattr(ic, "recognise_mixer_function", lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="capstone"):            # lift_linear's PARTIAL no-capstone
        ic.invert_elf_straightline(data, lengths=[4], funcs=["check"])


# ---- functions beyond read_elf's gadget-scan window; functions outside an executable section

@pytest.mark.needs_tool("clang")
def test_a_function_far_into_text_is_still_lifted(tmp_path):
    src = _branchless_asm(b"s1m!").replace("_pad:\n    ret\n", "_pad:\n    ret\n    .skip 300000\n")
    data = _assemble_x86_64(src, tmp_path)
    info = ic._read_elf(data)
    addr = dict(info["functions"])["check"]
    assert addr > 256 * 1024                       # past pwn.read_elf's GADGET_SCAN window
    rows = ic.invert_elf_straightline(data, lengths=[4], funcs=["check"])
    assert [r.value for r in rows] == [b"s1m!"]


_DATA_FUNC = """\
    .text
    .globl _pad
    .type _pad,@function
_pad:
    ret
    .data
    .byte 0
    .globl datafn
    .type datafn,@function
datafn:
    .byte 0xc3
"""


@pytest.mark.needs_tool("clang")
def test_a_named_function_outside_any_executable_section_raises(tmp_path):
    data = _assemble_x86_64(_DATA_FUNC, tmp_path)
    with pytest.raises(ic.InvertError, match="datafn .* not inside an executable section"):
        ic.invert_elf_straightline(data, lengths=[4], funcs=["datafn"])


@pytest.mark.needs_tool("clang")
def test_a_candidate_outside_any_executable_section_is_a_named_skip(tmp_path, monkeypatch):
    data = _assemble_x86_64(_DATA_FUNC, tmp_path)
    addr = dict(ic._read_elf(data)["functions"])["datafn"]
    monkeypatch.setattr(ic, "find_check_candidates", lambda info, max_funcs: [("datafn", addr)])
    rows = ic.invert_elf_straightline(data, lengths=[4])
    assert list(rows) == []
    assert any("datafn" in s and "not inside an executable section" in s for s in rows.skipped)


# ---- solve(): 'none' only after complete analysis; every incompleteness is 'unsure' and named

def _fake_rows(**attrs):
    rows = ic.ElfRows()
    for k, v in attrs.items():
        setattr(rows, k, v)
    return rows


def test_solve_is_none_when_every_elf_was_analysed_and_nothing_found(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    monkeypatch.setattr(ic, "invert_elf_straightline", lambda *a, **k: _fake_rows())
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert "every handout file was analysed" in res.notes


def test_solve_reports_a_budget_exhausted_mid_sweep(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    monkeypatch.setattr(ic, "invert_elf_straightline",
                        lambda *a, **k: _fake_rows(budget_exhausted=True))
    res = ic.solve(tmp_path, CSCTF, budget_s=30)
    assert res.status == "unsure"
    assert "files/bin: sweep stopped, time budget of 30 s used up" in res.notes


def test_solve_reports_a_function_level_skip_as_incomplete(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    monkeypatch.setattr(ic, "invert_elf_straightline",
                        lambda *a, **k: _fake_rows(skipped=["f at 0x10 is not inside X"]))
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "files/bin: f at 0x10 is not inside X" in res.notes


def test_solve_is_unsure_when_one_elf_was_skipped_and_another_analysed(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "a_ok")
    _write_elf_magic_junk(tmp_path / "files" / "b_skip")

    def fake(path, **_k):
        if Path(path).name == "b_skip":
            raise ic.ElfSkipped("architecture 'mips' is not lifted")
        return _fake_rows()

    monkeypatch.setattr(ic, "invert_elf_straightline", fake)
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "unsure"                    # not 'none': b_skip was never analysed
    assert "files/b_skip: architecture 'mips' is not lifted" in res.notes


def test_solve_names_handout_files_beyond_the_cap(tmp_path, monkeypatch):
    for i in range(ic.MAX_HANDOUT_FILES + 2):
        _write_elf_magic_junk(tmp_path / "files" / f"bin{i:02d}")
    tried = []
    monkeypatch.setattr(ic, "invert_elf_straightline",
                        lambda path, **k: tried.append(path) or _fake_rows())
    res = ic.solve(tmp_path, CSCTF)
    assert len(tried) == ic.MAX_HANDOUT_FILES
    assert res.status == "unsure"
    assert f"2 more ELF/class file(s) beyond the cap of {ic.MAX_HANDOUT_FILES} not tried" in res.notes


def test_solve_reports_a_recognised_mixer_function_as_a_lead(tmp_path, monkeypatch):
    _write_elf_magic_junk(tmp_path / "files" / "bin")
    mixers = [("mix", 0x40, 64, [("xorshift_right", 33), ("mul", 0x9D3A5F1B7C2E4A63)])]
    monkeypatch.setattr(ic, "invert_elf_straightline", lambda *a, **k: _fake_rows(mixers=mixers))
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "files/bin:mix at 0x40 is a 64-bit invertible mixer" in res.notes
    assert "mul 0x9d3a5f1b7c2e4a63" in res.notes
    assert [e.kind for e in res.evidence] == ["mixer-function"]


# ---- the word-mixer recogniser (hand-assembled x86: no tool needed)

def _mixer_check_amd64(key: bytes, mult: int) -> bytes:
    """mov rax,[rdi]; x ^= x>>33; x *= mult; x ^= x>>29; cmp x, T; sete al; movzx eax, al; ret --
    with T the forward value of `key` (computed here in plain Python, independent of the engine)."""
    x = int.from_bytes(key, "little")
    x ^= x >> 33
    x = (x * mult) & M64
    x ^= x >> 29
    return (bytes.fromhex("488b07" "4889c1" "48c1e921" "4831c8") + b"\x48\xb9" + struct.pack("<Q", mult)
            + bytes.fromhex("480fafc1" "4889c1" "48c1e91d" "4831c8") + b"\x48\xb9"
            + struct.pack("<Q", x) + bytes.fromhex("4839c8" "0f94c0" "0fb6c0" "c3"))


def test_invert_mixer_check_recovers_a_word_mixer_from_code():
    code = _mixer_check_amd64(b"Mx1ng!Ok", 0x9D3A5F1B7C2E4A63)
    sol = ic.invert_mixer_check(code, base=0x1000)
    assert sol is not None and sol.value == b"Mx1ng!Ok"
    assert sol.success_return == "nonzero"
    (off, width, ops, _target), = sol.words
    assert (off, width) == (0, 64)
    assert ops == [("xorshift_right", 33), ("mul", 0x9D3A5F1B7C2E4A63), ("xorshift_right", 29)]


def test_invert_mixer_check_never_pins_through_an_even_multiplier():
    # x * 6 is not a bijection: the word has several preimages, so nothing may be claimed.
    code = _mixer_check_amd64(b"Mx1ng!Ok", 6)
    assert ic.invert_mixer_check(code, base=0x1000) is None


def test_invert_mixer_check_models_rotate_add_xor_not_neg_inc_sub_and_jne_out():
    def rotl(v, s):
        return ((v << s) | (v >> (64 - s))) & M64
    x = int.from_bytes(b"r0t4tion", "little")
    x = rotl(x, 13)
    x = (x + 0x1234567) & M64
    x ^= 0x7654321
    x = rotl(x, 64 - 7)
    x ^= M64
    x = (-x) & M64
    x = (x + 1) & M64
    x = (x - 5) & M64
    body = (bytes.fromhex("488b07" "48c1c00d" "4805") + struct.pack("<i", 0x1234567) + b"\x48\x35"
            + struct.pack("<i", 0x7654321)
            + bytes.fromhex("48c1c807" "48f7d0" "48f7d8" "48ffc0" "4883e805") + b"\x48\xb9"
            + struct.pack("<Q", x) + bytes.fromhex("4839c8"))
    tail = bytes.fromhex("b801000000" "c3")
    code = body + b"\x0f\x85" + struct.pack("<i", len(tail) + 16) + tail   # jne past the region
    sol = ic.invert_mixer_check(code, base=0x2000)
    assert sol is not None and sol.value == b"r0t4tion"
    # the same compare with je (fail when EQUAL) accepts everything BUT the key: never pinned
    flipped = body + b"\x0f\x84" + struct.pack("<i", len(tail) + 16) + tail
    assert ic.invert_mixer_check(flipped, base=0x2000) is None


def test_invert_mixer_check_handles_i386_stack_argument_and_32_bit_words():
    v = int.from_bytes(b"i386", "little")
    v ^= v >> 16
    v = (v * 0x2C1B3C6D) & 0xFFFFFFFF
    code = (bytes.fromhex("8b4c2404" "8b01" "89c2" "c1ea10" "31d0" "69c0") + struct.pack("<I", 0x2C1B3C6D)
            + b"\x3d" + struct.pack("<I", v) + bytes.fromhex("0f94c0" "0fb6c0" "c3"))
    sol = ic.invert_mixer_check(code, arch="i386", bits=32, base=0x3000)
    assert sol is not None and sol.value == b"i386"
    assert sol.words[0][:2] == (0, 32)


def test_invert_mixer_check_refuses_loops_calls_and_writes_outside_the_stack():
    assert ic.invert_mixer_check(b"\xeb\xfe", base=0x1000) is None              # jmp to itself
    assert ic.invert_mixer_check(b"\xe8\x00\x00\x00\x00\xc3", base=0x1000) is None   # call, no resolver
    assert ic.invert_mixer_check(bytes.fromhex("48c707" "01000000" "b801000000" "c3"),
                                 base=0x1000) is None                              # mov qword [rdi], 1


def test_recognise_mixer_function_reads_the_ops_of_a_word_function():
    # mov rax, rdi; mov rcx, rax; shr rcx, 31; xor rax, rcx; movabs rcx, M; imul rax, rcx; ret
    code = (bytes.fromhex("4889f8" "4889c1" "48c1e91f" "4831c8") + b"\x48\xb9"
            + struct.pack("<Q", 0xA3B195354A39B70D) + bytes.fromhex("480fafc1" "c3"))
    assert ic.recognise_mixer_function(code, base=0x10) == (
        [("xorshift_right", 31), ("mul", 0xA3B195354A39B70D)], 64)
    # a function that only adds a constant is not reported as a mixer
    assert ic.recognise_mixer_function(bytes.fromhex("4889f8" "4883c005" "c3"), base=0x10) is None


def test_pin_and_check_refuses_an_unpinned_byte_and_a_failing_recheck():
    ld = ("ld", 64, 0)
    ops = [("xorshift_right", 33), ("mul", 0x9D3A5F1B7C2E4A63)]
    key = int.from_bytes(b"Pinned!!", "little")
    target = ic.apply_mixer(key, ops)
    pin = ("eq", 1, ic._apply_ops_nodes(ld, ops, 64), ic._c(target, 64))
    value, words = ic._pin_and_check([pin])
    assert value == b"Pinned!!" and words[0][2] == ops
    # a further byte is read but only through a non-bijective AND: not unique -> nothing claimed
    loose = ("eq", 1, ic._bin("and", 8, ("ld", 8, 8), ic._c(0x0F, 8)), ic._c(1, 8))
    assert ic._pin_and_check([pin, loose]) is None
    # an extra constraint the pinned input violates: the independent re-check rejects it
    veto = ("ne", 1, ("ld", 8, 0), ic._c(ord("P"), 8))
    assert ic._pin_and_check([pin, veto]) is None


def test_match_word_reads_an_xorshift_folded_into_a_compare():
    # the -O2 shape: (T ^ y) ^ (y >> 33) == 0, i.e. xorshift_right 33 of y, then compared to T
    y = ic._bin("mul", 64, ("ld", 64, 8), ic._c(0x1B873593CC9E2D51, 64))
    term = ic._bin("xor", 64, ic._bin("xor", 64, ic._c(0x5555, 64), y), ic._shift("shr", 64, y, 33))
    base, ops = ic._match_word(term)
    assert base == ("ld", 64, 8)
    assert ops == [("mul", 0x1B873593CC9E2D51), ("xorshift_right", 33), ("xor", 0x5555)]
    # a shift of a DIFFERENT value is not an xorshift
    other = ic._bin("xor", 64, y, ic._shift("shr", 64, ("ld", 64, 16), 33))
    assert ic._match_word(other) is None
    # an even multiplier is not a bijection: never matched as a mixer step
    assert ic._match_word(ic._bin("mul", 64, ("ld", 64, 0), ic._c(6, 64))) is None


# ---- the word-mixer pass end to end on compiled C (needs clang)

def _compile_c_x86_64(src: str, tmp_path: Path, *flags) -> bytes:
    c = tmp_path / "chk.c"
    c.write_text(src)
    o = tmp_path / "chkc.o"
    try:
        subprocess.run(["clang", "-target", "x86_64-linux-gnu", "-fno-stack-protector",
                        "-fcf-protection=none", *flags, "-c", str(c), "-o", str(o)],
                       check=True, capture_output=True, timeout=60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        pytest.skip(f"clang cannot emit an x86-64 Linux ELF here: {e}")
    return o.read_bytes()


_M1, _M2 = 0xA3B195354A39B70D, 0x1B873593CC9E2D51      # arbitrary odd multipliers (no signature)


def _fmix(x: int) -> int:
    x ^= x >> 31
    x = (x * _M1) & M64
    x ^= x >> 27
    x = (x * _M2) & M64
    x ^= x >> 33
    return x


_MIX_C = """\
typedef unsigned long long u64;
void pad(void) {}
static %(attr)s u64 mix(u64 x) { x ^= x >> 31; x *= 0x%(m1)xULL; x ^= x >> 27; x *= 0x%(m2)xULL;
                                  x ^= x >> 33; return x; }
"""


def _targets(key: bytes):
    return [_fmix(int.from_bytes(key[i:i + 8], "little")) for i in range(0, len(key), 8)]


@pytest.mark.needs_tool("clang")
def test_solve_inverts_an_inlined_three_word_mixer_to_the_flag(tmp_path):
    key = b"CSCTF{mixer_inverted_ok}"
    t = _targets(key)
    src = (_MIX_C % {"attr": "inline", "m1": _M1, "m2": _M2}
           + "int check(const u64 *k) { return (mix(k[0]) == 0x%xULL) & (mix(k[1]) == 0x%xULL)"
             " & (mix(k[2]) == 0x%xULL); }\n" % tuple(t))
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    (chal / "files" / "uplink").write_bytes(_compile_c_x86_64(src, tmp_path, "-O2"))
    res = ic.solve(chal, CSCTF, lengths=[4])
    assert res.status == "candidate"
    assert res.flags == ("CSCTF{mixer_inverted_ok}",)
    ev = [e.detail for e in res.evidence if e.kind == "recovered-input" and "word-mixer" in e.detail]
    assert ev and f"== {t[0]:#x}" in ev[0]          # the folded compare target, read from the code
    # a charset the key does not fit: the mixer row is filtered out, never reported
    rows = ic.invert_elf_straightline((chal / "files" / "uplink").read_bytes(), lengths=[4],
                                      charset=(0x61, 0x7A))
    assert list(rows) == []


@pytest.mark.needs_tool("clang")
def test_a_called_mixer_function_with_early_returns_is_inverted(tmp_path):
    key = b"callmix!_8bytes_"
    t = _targets(key)
    src = (_MIX_C % {"attr": "__attribute__((noinline))", "m1": _M1, "m2": _M2}
           + "int check(const u64 *k) { if (mix(k[0]) != 0x%xULL) return 0;\n"
             "  if (mix(k[1]) != 0x%xULL) return 0; return 1; }\n" % tuple(t))
    rows = ic.invert_elf_straightline(_compile_c_x86_64(src, tmp_path, "-O1"), lengths=[4])
    assert [(r.func, r.value) for r in rows if r.func == "check"] == [("check", key)]
    assert [(n, w, ops) for n, _a, w, ops in rows.mixers] == [
        ("mix", 64, [("xorshift_right", 31), ("mul", _M1), ("xorshift_right", 27), ("mul", _M2),
                     ("xorshift_right", 33)])]


@pytest.mark.needs_tool("clang")
def test_a_table_driven_mixer_loop_is_refused_but_its_mixer_is_a_lead(tmp_path):
    src = (_MIX_C % {"attr": "__attribute__((noinline))", "m1": _M1, "m2": _M2}
           + "u64 T[3] = {1, 2, 3};\n"
             "int check(const u64 *k) { for (int i = 0; i < 3; i++) if (mix(k[i]) != T[i]) return 0;"
             " return 1; }\n")
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    (chal / "files" / "loop").write_bytes(_compile_c_x86_64(src, tmp_path, "-O1", "-fno-unroll-loops"))
    res = ic.solve(chal, CSCTF, lengths=[4])
    assert res.status == "unsure"
    assert not any(e.kind == "recovered-input" for e in res.evidence)
    assert any(e.kind == "mixer-function" and "files/loop:mix" in e.detail for e in res.evidence)


@pytest.mark.needs_tool("clang")
def test_solve_is_none_after_analysing_an_uninvertible_looped_check(tmp_path):
    src = ("void pad(void) {}\n"
           "int check(const char *s) { for (int i = 0; s[i]; i++) if (s[i] != 'a' + i) return 0;"
           " return 1; }\n")
    chal = tmp_path / "chal"
    (chal / "files").mkdir(parents=True)
    (chal / "files" / "looped").write_bytes(_compile_c_x86_64(src, tmp_path, "-O1", "-fno-unroll-loops"))
    res = ic.solve(chal, CSCTF, lengths=[4])
    assert res.status == "none"
    assert "every handout file was analysed" in res.notes


# ---- the JVM per-character pass

class _Pool:
    """A minimal class-file constant pool builder (our own synthetic class files)."""

    def __init__(self):
        self.items: list = []
        self.idx: dict = {}

    def _add(self, key, raw):
        if key not in self.idx:
            self.items.append(raw)
            self.idx[key] = len(self.items)
        return self.idx[key]

    def utf8(self, s):
        b = s.encode()
        return self._add(("u", s), b"\x01" + struct.pack(">H", len(b)) + b)

    def cls(self, n):
        return self._add(("c", n), b"\x07" + struct.pack(">H", self.utf8(n)))

    def nat(self, n, d):
        return self._add(("n", n, d), b"\x0c" + struct.pack(">HH", self.utf8(n), self.utf8(d)))

    def mref(self, c, n, d):
        return self._add(("m", c, n, d), b"\x0a" + struct.pack(">HH", self.cls(c), self.nat(n, d)))

    def integer(self, v):
        return self._add(("i", v), b"\x03" + struct.pack(">i", v))


def _asm(items) -> bytes:
    """bytes, ("label", name), or (opcode, label) for a 2-byte relative branch."""
    off, labels = 0, {}
    for it in items:
        if isinstance(it, tuple) and it[0] == "label":
            labels[it[1]] = off
        else:
            off += 3 if isinstance(it, tuple) else len(it)
    out = bytearray()
    for it in items:
        if isinstance(it, tuple) and it[0] == "label":
            continue
        if isinstance(it, tuple):
            out += bytes([it[0]]) + struct.pack(">h", labels[it[1]] - len(out))
        else:
            out += it
    return bytes(out)


def _class_file(build, name="T") -> bytes:
    pool = _Pool()
    this, sup, code_u = pool.cls(name), pool.cls("java/lang/Object"), pool.utf8("Code")
    methods = [(pool.utf8(n), pool.utf8(d), acc, code) for n, d, acc, code in build(pool)]
    out = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, len(pool.items) + 1) + b"".join(pool.items)
    out += struct.pack(">HHHHH", 0x21, this, sup, 0, 0) + struct.pack(">H", len(methods))
    for ni, di, acc, code in methods:
        attr = struct.pack(">HHI", 16, 8, len(code)) + code + struct.pack(">HH", 0, 0)
        out += struct.pack(">HHHH", acc, ni, di, 1) + struct.pack(">HI", code_u, len(attr)) + attr
    return out


_STATIC = 0x0009
CHAR_AT = ("java/lang/String", "charAt", "(I)C")
LENGTH = ("java/lang/String", "length", "()I")
TO_CHARS = ("java/lang/String", "toCharArray", "()[C")


def _u2(v):
    return struct.pack(">H", v)


def _jvm_key_check(pool):
    """check(String)Z for "Jv4!": per-character blocks with stack shuffles (swap, dup_x1, dup2, pop2,
    dup_x2), toCharArray/caload, a method-local int table, irem, a concrete backward loop, ldc/ldc_w."""
    c0, c1, c2, c3 = (ord(c) for c in "Jv4!")
    t0 = (c0 - 13) ^ 0x55                                    # order-sensitive: kills a bad swap
    x = c1 << 3
    t1 = x ^ (x >> 5)
    t2 = 9 - (c2 + 77 + (-1))                                 # Java: -7 % 3 == -1; dup_x2 order
    t3 = -c3 + 100
    ca, ln, tc = pool.mref(*CHAR_AT), pool.mref(*LENGTH), pool.mref(*TO_CHARS)
    i0, i1 = pool.integer(t0), pool.integer(t1)
    assert i1 < 256                                           # ldc takes a one-byte index
    code = _asm([
        b"\x2a\xb6" + _u2(ln) + b"\x07", (0xA0, "FAIL"),            # length() != 4 -> fail
        # p0: (c0 - 13) ^ 0x55, via swap / dup_x1 / pop; compared to ldc_w
        b"\x2a\x03\xb6" + _u2(ca) + b"\x10\x0d\x5f\x5a\x57\x64\x10\x55\x82",
        b"\x13" + _u2(i0), (0xA0, "FAIL"),
        # p1: x = c1 << 3; x ^ (x >>> 5), via toCharArray / caload; dup2 + pop2; compared to ldc
        b"\x2a\xb6" + _u2(tc) + b"\x4c\x2b\x04\x34\x06\x78\x59\x08\x7c\x82",
        b"\x12" + bytes([i1]) + b"\x5c\x58", (0xA0, "FAIL"),
        # p2: 9 - (c2 + table[1] + (-7 % 3)), via newarray / iastore / iaload / irem / dup_x2 + pop2
        b"\x05\xbc\x0a\x4d\x2c\x04\x10\x4d\x4f",
        b"\x2a\x05\xb6" + _u2(ca) + b"\x2c\x04\x2e\x60\x10\xf9\x06\x70\x60\x08\x10\x09\x5b\x58\x64",
        b"\x11" + struct.pack(">h", t2), (0xA0, "FAIL"),
        # a concrete loop: for (i = 0; i < 3; i++) {}
        b"\x03\x3e", ("label", "LOOP"), b"\x1d\x06", (0xA2, "END"), b"\x84\x03\x01", (0xA7, "LOOP"),
        ("label", "END"),
        # p3: -c3 + 100
        b"\x2a\x06\xb6" + _u2(ca) + b"\x74\x10\x64\x60\x10" + bytes([t3]), (0xA0, "FAIL"),
        b"\x04\xac", ("label", "FAIL"), b"\x03\xac",
    ])
    return [("check", "(Ljava/lang/String;)Z", _STATIC, code)]


def test_invert_jvm_class_recovers_a_per_character_check_with_stack_shuffles():
    rows, skipped = ic.invert_jvm_class(_class_file(_jvm_key_check))
    assert [(r.func, r.value) for r in rows] == [("T.check", b"Jv4!")], skipped
    assert "invert_positions" in rows[0].detail and "length pinned" in rows[0].detail


def _single(code, desc="(Ljava/lang/String;)Z", acc=_STATIC, name="check"):
    return lambda pool: [(name, desc, acc, code(pool) if callable(code) else code)]


def _jvm_eval(blob: bytes, s: str) -> int:
    """Run the emulator's paths on a concrete string (by z3 substitution) and return the int result."""
    cls = ic.parse_jvm_class(blob)
    insns = ic._bytecode_lifters().lift_jvm_code(cls["methods"][0]["code"]).instructions
    emu = ic._JvmEmu(z3, cls["pool"])
    paths = emu.run(insns, 0, "Ljava/lang/String;")
    subs = [(v, z3.BitVecVal(ord(s[k]), 16)) for k, v in emu.chars.items()]
    subs.append((emu.len, z3.BitVecVal(len(s), 32)))
    hits = [ret for ret, st in paths
            if all(z3.is_true(z3.simplify(z3.substitute(c, *subs))) for c in st.cons)]
    assert len(hits) == 1
    return z3.simplify(z3.substitute(hits[0], *subs)).as_signed_long()


def _j32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v >> 31 else v


def _jdiv(a, b):
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _java_ops(a: int, b: int) -> int:
    """The arithmetic method below, in Java's 32-bit semantics, written independently in Python."""
    r = _j32(a - 200) >> 2
    r = _j32(r ^ ((_j32(a - 200) & 0xFFFFFFFF) >> 28))
    r = _j32(r + ((((b * 3) & 0xFF) ^ 0x80) - 0x80))
    r = _j32(r + ((((b * 1000) & 0xFFFF) ^ 0x8000) - 0x8000))
    r = _j32(r + ((a - 300) & 0xFFFF))
    r = _j32(r + ((a & 0x0F) | 0x30))
    r = _j32(r + _jdiv(-b, 7))
    r = _j32(r - (-b - 5 * _jdiv(-b, 5)))
    return r


def _ops_method(pool):
    ca = pool.mref(*CHAR_AT)
    return _asm([
        b"\x2a\x03\xb6" + _u2(ca) + b"\x3c",                       # a -> local 1
        b"\x2a\x04\xb6" + _u2(ca) + b"\x3d",                       # b -> local 2
        b"\x1b\x11\x00\xc8\x64\x05\x7a",                           # (a - 200) >> 2
        b"\x1b\x11\x00\xc8\x64\x10\x1c\x7c\x82",                   # ^ ((a - 200) >>> 28)
        b"\x1c\x06\x68\x91\x60",                                   # + (byte)(b * 3)
        b"\x1c\x11\x03\xe8\x68\x93\x60",                           # + (short)(b * 1000)
        b"\x1b\x11\x01\x2c\x64\x92\x60",                           # + (char)(a - 300)
        b"\x1b\x10\x0f\x7e\x10\x30\x80\x60",                       # + ((a & 15) | 48)
        b"\x1c\x74\x10\x07\x6c\x60",                               # + (-b / 7)
        b"\x1c\x74\x08\x70\x64",                                   # - (-b % 5)
        b"\xac",
    ])


@pytest.mark.parametrize("s", ["Az", "a\x01", "~0", "\x00\xff", "中é"])
def test_jvm_emulator_int_semantics_match_java(s):
    blob = _class_file(_single(_ops_method, desc="(Ljava/lang/String;)I"))
    assert _jvm_eval(blob, s) == _java_ops(ord(s[0]), ord(s[1]))


def _branch_method(pool):
    ca = pool.mref(*CHAR_AT)
    return _asm([
        b"\x2a\x03\xb6" + _u2(ca) + b"\x10\x64\x64",              # d = c0 - 100
        b"\x59", (0x9B, "L1"),                                    # dup; iflt L1
        b"\x59", (0x99, "L2"),                                    # dup; ifeq L2
        b"\x59\x10\x0a", (0xA3, "L3"),                            # dup; 10; if_icmpgt L3
        b"\x57\x07\xac",                                          # pop; return 4
        ("label", "L1"), b"\x57\x04\xac", ("label", "L2"), b"\x57\x05\xac",
        ("label", "L3"), b"\x57\x06\xac",
    ])


@pytest.mark.parametrize("c, want", [(50, 1), (100, 2), (120, 3), (105, 4), (110, 4), (111, 3)])
def test_jvm_emulator_branches_follow_the_comparison(c, want):
    blob = _class_file(_single(_branch_method, desc="(Ljava/lang/String;)I"))
    assert _jvm_eval(blob, chr(c)) == want


def _eq_char(pool, k, ch, label="FAIL"):
    """aload_0; bipush k; charAt; bipush ch; if_icmpne label"""
    ca = pool.mref(*CHAR_AT)
    return [b"\x2a\x10" + bytes([k]) + b"\xb6" + _u2(ca) + b"\x10" + bytes([ord(ch)]), (0xA0, label)]


_TRUE_FAIL = [b"\x04\xac", ("label", "FAIL"), b"\x03\xac"]


def test_an_unchecked_length_gives_the_shortest_accepted_key():
    blob = _class_file(_single(lambda p: _asm(_eq_char(p, 0, "Q") + _TRUE_FAIL)))
    rows, _ = ic.invert_jvm_class(blob)
    assert [r.value for r in rows] == [b"Q"]
    assert "shortest accepted key" in rows[0].detail


def test_a_length_longer_than_the_checked_positions_is_not_unique():
    def code(p):
        return _asm([b"\x2a\xb6" + _u2(p.mref(*LENGTH)) + b"\x06", (0xA0, "FAIL")]
                    + _eq_char(p, 0, "Q") + _TRUE_FAIL)
    rows, skipped = ic.invert_jvm_class(_class_file(_single(code)))
    assert rows == []
    assert skipped == [("T.check", "the length is 3 but only 1 position(s) are checked, "
                                   "so the key is not unique")]


def test_a_position_never_read_is_not_unique():
    rows, skipped = ic.invert_jvm_class(_class_file(_single(
        lambda p: _asm(_eq_char(p, 1, "Q") + _TRUE_FAIL))))
    assert rows == [] and "position(s) [0] are never read" in skipped[0][1]


def test_two_accepting_paths_go_to_one_joint_proof():
    # if (c0 == 'K') return true; if (c0 + 1 == 'L') return true; return false;  (both accept "K")
    def code(p):
        ca = p.mref(*CHAR_AT)
        return _asm([b"\x2a\x03\xb6" + _u2(ca) + b"\x10\x4b", (0xA0, "NEXT"), b"\x04\xac",
                     ("label", "NEXT"), b"\x2a\x03\xb6" + _u2(ca) + b"\x04\x60\x10\x4c", (0xA0, "FAIL")]
                    + _TRUE_FAIL)
    rows, skipped = ic.invert_jvm_class(_class_file(_single(code)))
    assert [r.value for r in rows] == [b"K"], skipped
    assert "joint z3 solve" in rows[0].detail


def test_two_accepting_paths_with_different_keys_are_not_unique():
    def code(p):
        return _asm(_eq_char(p, 0, "K", "NEXT") + [b"\x04\xac", ("label", "NEXT")]
                    + _eq_char(p, 0, "L") + _TRUE_FAIL)
    rows, skipped = ic.invert_jvm_class(_class_file(_single(code)))
    assert rows == [] and skipped[0][1].startswith("characters not unique")


def test_a_method_that_never_returns_true_and_unmodelled_calls_are_named():
    def build(p):
        eq = p.mref("java/lang/String", "equals", "(Ljava/lang/Object;)Z")
        return [("never", "(Ljava/lang/String;)Z", _STATIC, b"\x03\xac"),
                ("eq", "(Ljava/lang/String;)Z", _STATIC, b"\x2a\x2a\xb6" + _u2(eq) + b"\xac"),
                ("notacheck", "(I)Z", _STATIC, b"\x04\xac")]
    rows, skipped = ic.invert_jvm_class(_class_file(build))
    assert rows == []
    assert skipped == [("T.never", "no path returns true"),
                       ("T.eq", "a call to String.equals(Ljava/lang/Object;)Z")]


def test_an_instance_method_reads_its_input_from_local_one():
    def code(p):
        ca = p.mref(*CHAR_AT)
        return _asm([b"\x2b\x03\xb6" + _u2(ca) + b"\x10\x5a", (0xA0, "FAIL")] + _TRUE_FAIL)
    rows, _ = ic.invert_jvm_class(_class_file(_single(code, acc=0x0001)))
    assert [r.value for r in rows] == [b"Z"]


def test_a_symbolic_divisor_is_refused():
    def code(p):
        return b"\x10\x64\x2a\x03\xb6" + _u2(p.mref(*CHAR_AT)) + b"\x6c\xac"     # 100 / c0
    rows, skipped = ic.invert_jvm_class(_class_file(_single(code)))
    assert rows == [] and "must be concrete" in skipped[0][1]


def test_unknown_method_names_and_malformed_classes_raise():
    blob = _class_file(_jvm_key_check)
    with pytest.raises(ic.InvertError, match="nope"):
        ic.invert_jvm_class(blob, methods=["nope"])
    with pytest.raises(ic.InvertError):
        ic.parse_jvm_class(blob[:40])


def test_class_magic_is_told_apart_from_a_mach_o_universal_binary():
    assert ic.is_class_file(b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
    assert not ic.is_class_file(b"\xca\xfe\xba\xbe\x00\x00\x00\x02")      # fat header, 2 archs


def test_solve_inverts_a_class_file_in_the_handout_to_the_flag(tmp_path):
    flag = "CSCTF{jvm}"

    def code(p):
        ca = p.mref(*CHAR_AT)
        items = [b"\x2a\xb6" + _u2(p.mref(*LENGTH)) + b"\x10" + bytes([len(flag)]), (0xA0, "FAIL")]
        for k, ch in enumerate(flag):                  # (s.charAt(k) ^ 0x2a) != (ch ^ 0x2a) -> fail
            items += [b"\x2a\x10" + bytes([k]) + b"\xb6" + _u2(ca) + b"\x10\x2a\x82\x10"
                      + bytes([ord(ch) ^ 0x2A]), (0xA0, "FAIL")]
        return _asm(items + _TRUE_FAIL)
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "trypo").write_bytes(_class_file(_single(code)))   # extension-less
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "candidate", res.notes
    assert res.flags == (flag,)


def test_solve_retries_a_method_over_printable_ascii_and_says_so(tmp_path):
    # (c0 & 0x7f) == 'A' has many 16-bit solutions but exactly one printable one.
    def code(p):
        ca = p.mref(*CHAR_AT)
        return _asm([b"\x2a\xb6" + _u2(p.mref(*LENGTH)) + b"\x04", (0xA0, "FAIL"),
                     b"\x2a\x03\xb6" + _u2(ca) + b"\x10\x7f\x7e\x10\x41", (0xA0, "FAIL")] + _TRUE_FAIL)
    blob = _class_file(_single(code))
    rows, skipped = ic.invert_jvm_class(blob)
    assert rows == [] and skipped[0][1].startswith("characters not unique")
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "C.class").write_bytes(blob)
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "T.check accepts 'A'" in res.notes
    assert "unique only among characters in (32, 126)" in res.notes


def test_solve_names_an_unreadable_class_file(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "bad.class").write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00")
    res = ic.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "files/bad.class: not a readable class file" in res.notes


_JAVA_SRC = """\
public class Chk {
    public static boolean check(String s) {
        if (s.length() != 6) return false;
        int a = s.charAt(0); a = (a * 7 + 3) ^ 0x55;
        if (a != ((('J' * 7) + 3) ^ 0x55)) return false;
        int b = s.charAt(1); b = (b * 0x9e37) ^ 0x1234;
        if (b != ((97 * 0x9e37) ^ 0x1234)) return false;
        if ((s.charAt(2) ^ 0x21) != ('v' ^ 0x21)) return false;
        if (s.charAt(3) - 7 != 'a' - 7) return false;
        int e = s.charAt(4) * 31 + 17; e = e ^ (e >>> 3);
        int ee = 'O' * 31 + 17; ee = ee ^ (ee >>> 3);
        if (e != ee) return false;
        return s.charAt(5) + 1 == 'K' + 1;
    }
    public static boolean tied(String s) {
        return s.length() == 2 && s.charAt(0) + s.charAt(1) == 200 && s.charAt(0) - s.charAt(1) == 2;
    }
    public static boolean loose(String s) {
        return (s.charAt(0) & 0x0f) == 1;
    }
}
"""


@pytest.mark.needs_tool("javac")
def test_invert_jvm_class_on_javac_output(tmp_path):
    src = tmp_path / "Chk.java"
    src.write_text(_JAVA_SRC)
    try:
        subprocess.run(["javac", "--release", "8", "-nowarn", "-d", str(tmp_path), str(src)],
                       check=True, capture_output=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        pytest.skip(f"javac could not compile the fixture here: {e}")
    rows, skipped = ic.invert_jvm_class((tmp_path / "Chk.class").read_bytes())
    assert sorted((r.func, r.value) for r in rows) == [("Chk.check", b"JavaOK"), ("Chk.tied", b"ec")]
    assert [m for m, _ in skipped] == ["Chk.loose"]


def test_two_accepting_x86_paths_are_not_pinned():
    # if (k == A) return 1; return k == B;  -- two different accepted inputs: nothing may be claimed
    a, b = 0x1111222233334444, 0x5555666677778888
    tail = bytes.fromhex("b801000000" "c3")
    body = (b"\x48\xb9" + struct.pack("<Q", b) + bytes.fromhex("4839c8" "0f94c0" "0fb6c0" "c3"))
    code = (bytes.fromhex("488b07") + b"\x48\xb9" + struct.pack("<Q", a) + bytes.fromhex("4839c8")
            + b"\x74" + bytes([len(body)]) + body + tail)
    assert ic.invert_mixer_check(code, base=0x1000) is None
    # the same shape where both paths accept the SAME word: the paths are explored, but an OR of two
    # paths is still refused (the pass pins one conjunction only)
    one = (bytes.fromhex("488b07") + b"\x48\xb9" + struct.pack("<Q", a) + bytes.fromhex("4839c8")
           + b"\x75" + bytes([len(tail)]) + tail + bytes.fromhex("31c0" "c3"))
    sol = ic.invert_mixer_check(one, base=0x1000)                 # jne to `return 0`: one path
    assert sol is not None and sol.value == a.to_bytes(8, "little")


def test_a_function_with_a_check_is_not_a_pure_mixer():
    # cmp rdi, 5; jne <out of region>; mov rax, rdi; imul rax, rax, 0x1234567; ret
    code = (bytes.fromhex("4883ff05") + b"\x0f\x85" + struct.pack("<i", 0x100)
            + bytes.fromhex("4889f8" "4869c067452301" "c3"))
    assert ic.recognise_mixer_function(code, base=0x10) is None
    assert ic.recognise_mixer_function(code[10:], base=0x1A) == ([("mul", 0x1234567)], 64)


def test_a_zero_extended_32_bit_load_never_equals_a_wider_constant():
    def check(t):                       # mov eax, [rdi]; movabs rcx, t; cmp rax, rcx; sete; movzx; ret
        return (bytes.fromhex("8b07") + b"\x48\xb9" + struct.pack("<Q", t)
                + bytes.fromhex("4839c8" "0f94c0" "0fb6c0" "c3"))
    sol = ic.invert_mixer_check(check(0x64636261), base=0x1000)
    assert sol is not None and sol.value == b"abcd"
    assert ic.invert_mixer_check(check(0x1_64636261), base=0x1000) is None


def test_flags_after_imul_are_undefined_so_a_sete_on_them_is_refused():
    # mov rax,[rdi]; movabs rcx, C; imul rax, rcx; sete al; movzx eax, al; ret  (ZF undefined)
    code = (bytes.fromhex("488b07") + b"\x48\xb9" + struct.pack("<Q", 0x9D3A5F1B7C2E4A63)
            + bytes.fromhex("480fafc1" "0f94c0" "0fb6c0" "c3"))
    assert ic.invert_mixer_check(code, base=0x1000) is None
