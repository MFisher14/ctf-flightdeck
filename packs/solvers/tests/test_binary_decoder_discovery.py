"""B-166: automatic decoder-function discovery bound to the ELF emulator and decompiler leads.

Covers ``solvers/binary/decoder_discovery.py`` (function map, call-site binding, B-011 and B-026 leads,
ranking, evaluation, the engine entry) and the generalised ``solvers/binary/native_behavior.py`` (targets
from the image-wide discovery, the exact evaluator's several arguments, load-address layouts and relocated
slots).

The fixtures are our own C and assembly sources, compiled by clang and laid out by the test linker
(``tests/decoder_discovery_fixtures.py`` -> ``tests/fixtures/decoder_discovery``).  They are committed, so
these tests need no compiler; one ``needs_tool("clang")`` test rebuilds them and one
``needs_tool("radare2")`` test runs B-011's real decompiler over one.  Nothing is run on the host: images
are read, and their functions emulated.  Every expected value is computed here by an independent Python
model of the C function, never read back from the engine or from the fixture builder.

Time: no test bounds wall-clock time.  Work is bounded by the emulator's own block/memory budgets, which
the budget tests set explicitly.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT, ROOT / "solvers" / "toolkits", ROOT / "solvers" / "common", ROOT / "solvers" / "binary"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import decoder_discovery as dd          # noqa: E402  (flat import, the engine sys.path)
import native_behavior as nb            # noqa: E402
import native_image as ni               # noqa: E402
from ctf import event                   # noqa: E402
from ctf.engines import manifest as _manifest, router as _router, runner as _runner   # noqa: E402
from ctf.result import SolverResult     # noqa: E402

CSCTF = event.load("csctf")
FIX = Path(__file__).resolve().parent / "fixtures" / "decoder_discovery"
M64 = (1 << 64) - 1
M32 = 0xFFFFFFFF

# Unicorn is in the venv, but native_emulate turns it off on a Darwin/arm64 host whose cache-line size is
# unreadable.  The tests that need the whole-image emulator say so and report NOT RUN there.
needs_unicorn = pytest.mark.skipif(not ni.UNICORN_AVAILABLE,
                                   reason="needs_tool: unicorn is guarded off on this host (native_emulate)")

# ------------------------------------------------------------------ the plaintexts and independent models
FLAG = b"CSCTF{d3c0d3r_b0und_at_th3_c4ll_s1te}"
STATE_FLAG = b"CSCTF{c0nstruct0r_pr3p4red_th3_t4ble}"
STATE_BLOB = b"the quick brown fox jumps over the lazy dog"
LEAD_FLAG = b"CSCTF{th3_l34d_b0und_th3_k3y}"
NEVER_FLAG = b"CSCTF{n0th1ng_c4lls_th1s_0ne}"
PRINT_FLAG = b"CSCTF{pr1nt3d_by_th3_d3c0d3r}"
INOUT_PLAIN = b"caller filled this first"
DECOY_A = "CSCTF{th1s_0ne_is_a_d3c0y}"
DECOY_B = "CSCTF{th1s_0ne_is_r34l}"


def m_enc(plain: bytes, key: int) -> bytes:
    """What dd_xor_decode undoes (the bytes main passes it)."""
    return bytes(p ^ ((key + 7 * i) & 0xFF) for i, p in enumerate(plain))


def m_mix(x: int) -> int:
    x ^= x >> 31
    x = (x * 0x6F2B8A4D93C5E1B7) & M64
    x ^= x >> 27
    x = (x * 0xC3A5F18E7D2B964B) & M64
    return x ^ (x >> 33)


def m_round(x: int, k: int) -> int:
    for i in range(k):
        x = ((x ^ i) * 0x100000001B3) & M64
    return x


def m_sum(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = (((h << 5) | (h >> 27)) & M32) ^ b
    return h


def m_late(k: int) -> int:
    v = 0x9E3779B9
    for i in range(16):
        v ^= (k + i) & M32
        v = ((v << 5) | (v >> 27)) & M32
        v = (v * 0x01000193) & M32
    return v


def m_orphan(k: int) -> int:
    v = (k ^ 0x5BD1E995) & M32
    for _ in range(4):
        v = ((v >> 3) ^ (v * 0x2545F491)) & M32
    return v


def m_checksum(text: bytes) -> int:
    """dd_checksum: h = 7; h = h * 31 + c, in a 32-bit int."""
    h = 7
    for c in text:
        h = (h * 31 + c) & M32
    return h


def m_twin_a(x: int) -> int:
    x ^= x >> 7
    x = (x * 0x9E5B3A71) & M64
    return x ^ (x >> 11)


def m_twin_b(x: int) -> int:
    x = (x + 0x1234567) & M64
    x = (x * 0x85D1C3A9) & M64
    return x ^ (x >> 13)


# ------------------------------------------------------------------ helpers
def blob(name: str) -> bytes:
    return (FIX / (name + ".so")).read_bytes()


_MODELS: dict = {}


def model(name: str) -> dd.Model:
    if name not in _MODELS:
        _MODELS[name] = dd.analyse(blob(name))
    return _MODELS[name]


def fn(m: dd.Model, name: str) -> dd.Func:
    got = [f for f in m.funcs.values() if f.name == name]
    assert len(got) == 1, (name, [f.label for f in m.funcs.values()])
    return got[0]


def site(m: dd.Model, caller: str, callee: str, index: int = 0) -> dd.Site:
    rows = [s for s in m.sites if s.caller == fn(m, caller).addr and s.target == fn(m, callee).addr]
    assert len(rows) > index, (caller, callee, rows)
    return sorted(rows, key=lambda s: s.addr)[index]


def challenge(tmp_path: Path, *names: str) -> Path:
    files = tmp_path / "files"
    files.mkdir(parents=True, exist_ok=True)
    for k, name in enumerate(names):
        shutil.copy(FIX / (name + ".so"), files / ("chal%d" % k if k else "chal"))
    return tmp_path


def outputs(m: dd.Model, name: str, args):
    out = dd.evaluate(m, fn(m, name).addr, args)
    return {o.kind: o.data for o in out.outputs}, out


def details(result: SolverResult, kind: str):
    return [e.detail for e in result.evidence if e.kind == kind]


ARCHES = ("x86_64", "arm64")


# ================================================================== function map
def test_the_fixtures_hold_no_plaintext_flag():
    # The engine has to DECODE: a flag readable with strings(1) would let a broken decoder pass.
    for path in sorted(FIX.glob("*.so")):
        assert b"CSCTF{" not in path.read_bytes(), path.name


@pytest.mark.parametrize("arch", ARCHES)
def test_function_map_names_every_function_and_its_extent(arch):
    m = model("dd_flag_" + arch)
    names = {f.name for f in m.funcs.values() if f.stub is None}
    assert {"dd_abi", "dd_xor_decode", "dd_mix", "dd_word", "dd_sum", "dd_checksum", "dd_round", "dd_first",
            "main"} <= names
    order = sorted((f.addr, f.end) for f in m.funcs.values())
    for (a, end), (b, _e) in zip(order, order[1:]):
        if m.img.seg_of(a) == m.img.seg_of(b):
            assert end == b                    # a function runs to the next function start


def test_a_stripped_image_gets_its_functions_from_call_targets():
    full, bare = model("dd_flag_x86_64"), model("dd_flag_x86_64_stripped")
    assert not bare.img.symtab                 # really stripped: only the dynamic exports are named
    for name in ("dd_xor_decode", "dd_mix", "dd_word", "dd_sum", "dd_checksum", "dd_first"):
        f = bare.funcs.get(fn(full, name).addr)
        assert f is not None, name
        assert f.name is None and f.sources == {"call-target"}
        assert f.label == "fcn.%08x" % f.addr
        assert f.arity == fn(full, name).arity


@pytest.mark.parametrize("arch", ARCHES)
def test_a_plt_stub_resolves_to_the_function_of_the_same_image(arch):
    m = model("dd_flag_" + arch)
    stubs = {f.stub for f in m.funcs.values() if f.stub is not None}
    assert ("resolved", fn(m, "dd_round").addr) in stubs
    assert ("import", "puts") in stubs
    # main calls dd_round through the PLT: the call site names the function, not the stub
    assert site(m, "main", "dd_round").args[:2] == (("int", 0x10), ("int", 3))
    assert "puts" in fn(m, "main").scan.imports
    assert fn(m, "dd_round").addr not in [a for a, f in m.funcs.items() if f.stub]


@pytest.mark.parametrize("arch", ARCHES)
def test_arity_is_the_argument_registers_read_before_written(arch):
    m = model("dd_flag_" + arch)
    want = {"dd_abi": 0, "dd_xor_decode": 4, "dd_mix": 1, "dd_word": 1, "dd_sum": 2, "dd_checksum": 1,
            "dd_round": 2, "dd_first": 0, "dd_len": 1, "main": 2}
    assert {n: fn(m, n).arity for n in want} == want
    # dd_len reads nothing itself: it hands its argument, unwritten, to strlen (a modelled libc function)
    assert fn(m, "dd_len").scan.used == set() and fn(m, "dd_len").scan.passes[0][0] == ("libc", "strlen")


def test_arity_counts_an_argument_handed_unwritten_to_a_callee():
    # tk_tail and tk_frame set every argument themselves; tk_join passes its own rsi/x1 test and nothing on
    for name in ("dd_track_x86_64", "dd_track_arm64"):
        m = model(name)
        assert fn(m, "tk_sink").arity == 3
        assert fn(m, "tk_tail").arity == 0
        assert fn(m, "tk_join").arity == 2      # it reads its second argument (the branch condition)
        assert fn(m, "tk_wrap").arity == 2      # sets the third itself, hands the first two on to tk_sink
        assert fn(m, "tk_after").arity == 0     # a register read AFTER a call is not this function's argument
    assert fn(model("dd_track_x86_64"), "tk_arith").arity == 0     # `xor edx, edx` reads nothing
    assert fn(model("dd_track_arm64"), "tk_movk_arg").arity == 1   # movk keeps (reads) the rest of x0


def test_scan_counts_structure_not_constants():
    x86, arm = model("dd_flag_x86_64"), model("dd_flag_arm64")
    mix = fn(x86, "dd_mix").scan
    assert (mix.transform, mix.loops, mix.byte_mem, mix.table, mix.returns) == (8, 0, 0, 0, True)   # 3 xor 3 shr 2 imul
    assert fn(arm, "dd_mix").scan.transform == 5                    # 3 eor (the shifts folded in), 2 mul
    for m in (x86, arm):
        dec = fn(m, "dd_xor_decode").scan
        assert dec.loops >= 1 and dec.byte_mem >= 1 and dec.table >= 1 and dec.returns
        assert fn(m, "dd_checksum").scan.loops >= 1
        assert fn(m, "dd_abi").scan.transform == 0 and fn(m, "dd_abi").scan.loops == 0
    tx, ta = model("dd_track_x86_64"), model("dd_track_arm64")
    assert fn(tx, "tk_env").scan.env == 2 and fn(ta, "tk_env").scan.env == 1      # %fs read + syscall; svc
    assert fn(tx, "tk_sink").scan.env == 0
    assert fn(tx, "tk_unary_ind").scan.indirect == 1 and fn(tx, "tk_unary_ok").scan.indirect == 0
    assert fn(tx, "tk_unary_imp").scan.imports == ["puts"]
    assert not fn(tx, "tk_unary_noret").scan.returns and fn(tx, "tk_unary_ok").scan.returns
    assert fn(tx, "tk_unary_trunc").scan.truncated and not fn(tx, "tk_unary_ok").scan.truncated


def test_the_call_sweep_resumes_after_bytes_that_do_not_decode():
    m = model("dd_track_x86_64")
    # tk_only is called only from tk_last, which sits after tk_unary_trunc's undecodable byte
    assert "call-target" in fn(m, "tk_only").sources
    assert site(m, "tk_last", "tk_only").args[0] == ("int", 4)


def test_the_image_must_load():
    with pytest.raises(dd.Decline):
        dd.analyse(b"\x7fELF" + b"\x00" * 200)
    with pytest.raises(dd.Decline):
        dd.analyse("not bytes")


# ================================================================== call-site binding
@pytest.mark.parametrize("arch", ARCHES)
def test_call_sites_bind_constants_image_pointers_and_stack_buffers(arch):
    m = model("dd_flag_" + arch)
    args = site(m, "main", "dd_xor_decode").args
    assert args[0][0] == "ptr" and args[1] == ("int", len(FLAG)) and args[2] == ("int", 0x5A)
    assert args[3][0] == "stk"
    # the pointer really is the table the decoder reads: its bytes are the independent encoding of FLAG
    assert m.img.file_bytes(args[0][1], len(FLAG)) == m_enc(FLAG, 0x5A)
    assert site(m, "main", "dd_mix").args[0] == ("int", 0x1337)
    assert site(m, "main", "dd_word").args[0] == ("int", 2)
    assert site(m, "main", "dd_sum").args[:2] == (args[0], ("int", len(FLAG)))
    assert site(m, "main", "dd_checksum").args[0] is None        # argv[1]: a run-time value


def test_x86_tracker_forgets_at_a_branch_target():
    m = model("dd_track_x86_64")
    assert site(m, "tk_join", "tk_sink").args[:3] == (None, ("int", 3), None)


def test_x86_tracker_forgets_caller_saved_registers_at_a_call_and_keeps_callee_saved():
    m = model("dd_track_x86_64")
    assert site(m, "tk_clobber", "tk_other").args[0] == ("int", 5)
    assert site(m, "tk_clobber", "tk_sink").args[:3] == (None, ("int", 0x77), ("int", 1))


def test_x86_tracker_reads_stack_slots_until_a_call():
    m = model("dd_track_x86_64")
    first, second = site(m, "tk_slot", "tk_sink", 0), site(m, "tk_slot", "tk_sink", 1)
    assert first.args[:3] == (("int", 0x2A), ("int", 0x10), ("stk", ("rsp", 16)))
    assert second.args[:3] == (None, ("int", 2), ("int", 3))


def test_x86_tracker_forgets_a_stack_slot_another_store_overlaps():
    m = model("dd_track_x86_64")
    # [rsp+8] was 0x10 until a 4-byte store hit its upper half; [rsp+16] was 9 until an `add` changed it in
    # place; [rsp] was stored once and is still known
    assert site(m, "tk_overlap", "tk_sink").args[:3] == (None, ("int", 7), None)


def test_x86_tracker_follows_pointer_arithmetic_got_loads_and_narrow_writes():
    m = model("dd_track_x86_64")
    first, second = site(m, "tk_arith", "tk_sink", 0), site(m, "tk_arith", "tk_sink", 1)
    table = first.args[0]
    assert table[0] == "ptr" and m.img.file_bytes(table[1] - 8, 16) == (1).to_bytes(8, "little") + (2).to_bytes(8, "little")
    assert first.args[1:3] == (("int", 0x1244), ("int", 0))
    assert second.args[0] == ("ptr", m.data_symbols()["tk_global"])        # through the GOT
    assert second.args[1] == ("int", 0xFFFFFFFF)                           # a 32-bit register copy
    assert second.args[2] is None                                          # `mov dl, 1`: a partial write


def test_x86_tracker_records_a_tail_call_and_distrusts_a_moved_frame():
    m = model("dd_track_x86_64")
    tail = site(m, "tk_tail", "tk_sink")
    assert tail.tail and tail.args[:3] == (("int", 1), ("int", 2), ("int", 3))
    assert not site(m, "tk_join", "tk_sink").tail
    assert site(m, "tk_frame", "tk_sink").args[:3] == (None, ("int", 1), ("int", 2))


def test_a64_tracker_builds_movk_constants_and_page_pointers():
    m = model("dd_track_arm64")
    args = site(m, "tk_movk", "tk_sink").args
    assert args[0] == ("int", 0x9ABC12345678) and args[2] == ("int", 7)
    assert args[1][0] == "ptr" and m.img.file_bytes(args[1][1], 8) == (2).to_bytes(8, "little")


def test_a64_tracker_forgets_at_branch_targets_calls_and_frame_moves():
    m = model("dd_track_arm64")
    assert site(m, "tk_join", "tk_sink").args[:3] == (None, ("int", 3), None)
    assert site(m, "tk_clobber", "tk_sink").args[:3] == (None, ("int", 0x77), ("int", 1))
    first, second = site(m, "tk_stack", "tk_sink", 0), site(m, "tk_stack", "tk_sink", 1)
    assert first.args[:3] == (("stk", ("sp", 8)), ("int", 1), ("int", 2))
    assert second.args[:3] == (None, ("int", 1), ("int", 2))               # sp moved after the add
    tail = site(m, "tk_tail", "tk_sink")
    assert tail.tail and tail.args[:3] == (("int", 1), ("int", 2), ("int", 3))
    sub = site(m, "tk_sub", "tk_sink").args
    assert sub[0] == ("int", 0x30) and sub[2] == ("int", 0)
    assert sub[1][0] == "ptr" and m.img.file_bytes(sub[1][1], 8) == (3).to_bytes(8, "little")


# ================================================================== B-011 leads (pseudocode)
PSEUDO = '''
int main(int argc,char **argv,char **envp)
{
    uchar auStack_68 [72];
    sym.dd_xor_decode(0x2080,0x25,0x5a,auStack_68);
    loc.imp.puts(auStack_68);
    iVar1 = sym.dd_mix(0x1337);
    if (iVar1 == 0) { return 1; }
    iVar3 = sym.plt.dd_round(0x10,3);
    iVar4 = fcn.%(sum)08x((char *)&DAT_%(dat)08x, 37U);
    FUN_%(ghidra)08x("a\\x41\\n", -1);
    sym.dd_checksum(argv[1]);
    return sizeof(iVar4);
}
'''


def test_leads_read_calls_and_literals_out_of_pseudocode():
    m = model("dd_flag_x86_64")
    enc = site(m, "main", "dd_xor_decode").args[0][1]
    text = PSEUDO % dict(sum=fn(m, "dd_sum").addr, dat=enc, ghidra=fn(m, "dd_word").addr + 0x100000)
    leads = dd.leads_from_text(m, text, "main.c", defined="main")
    by = {}
    for ld in leads:
        by.setdefault(ld.target, []).append(ld.args)
    assert by[fn(m, "dd_xor_decode").addr] == [(("int", 0x2080), ("int", 0x25), ("int", 0x5A), None)]
    assert by[fn(m, "dd_mix").addr] == [(("int", 0x1337),)]
    assert by[fn(m, "dd_round").addr] == [(("int", 0x10), ("int", 3))]            # sym.plt.<name>
    assert by[fn(m, "dd_sum").addr] == [(("ptr", enc), ("int", 37))]              # fcn.<addr>, &DAT_, 37U
    assert by[fn(m, "dd_word").addr] == [(("bytes", b"aA\n\x00"), ("int", M64))]  # Ghidra's PIE base, -1
    assert by[fn(m, "dd_checksum").addr] == [(None,)]
    assert fn(m, "main").addr not in by          # its own signature line is not a call
    assert len(leads) == 6                       # puts (an import), if, sizeof: none is a lead
    assert all(ld.source == "main.c" for ld in leads)


def test_a_lead_argument_names_a_data_symbol():
    m = model("dd_track_x86_64")
    text = "x = sym.tk_sink(obj.tk_global, &tk_global, tk_missing);"
    (lead,) = dd.leads_from_text(m, text, "entry0.c")
    addr = m.data_symbols()["tk_global"]
    assert lead.args == (("ptr", addr), ("ptr", addr), None)


def test_an_unterminated_or_unknown_call_is_no_lead():
    m = model("dd_flag_x86_64")
    assert dd.leads_from_text(m, "sym.dd_mix(0x1337", "main.c") == []
    assert dd.leads_from_text(m, "sym.not_there(1); fcn.7fffffff(2);", "main.c") == []


def test_align_shifts_a_lead_until_it_agrees_with_the_call_site():
    m = model("dd_lead_x86_64")
    s = site(m, "main", "dd_keyed")
    assert s.args[0][0] == "ptr" and s.args[1] == ("int", len(LEAD_FLAG)) and s.args[2] is None
    enc = s.args[0][1]
    # r2ghidra's recovered signature carries two extra leading parameters
    lead = (None, None, ("int", enc), ("int", len(LEAD_FLAG)), ("int", 0x5A), None)
    assert dd._align(m, s.args, lead, 4) == (("ptr", enc), ("int", len(LEAD_FLAG)), ("int", 0x5A), s.args[3])
    # a literal that contradicts what the site binds: no alignment, nothing is filled in
    assert dd._align(m, s.args, (("int", enc), ("int", 99), ("int", 0x5A), None), 4) is None
    # a literal where the site passes a stack buffer contradicts too
    assert dd._align(m, s.args, (("int", enc), ("int", len(LEAD_FLAG)), ("int", 0x5A), ("int", 1)), 4) is None
    # two shifts that both agree: ambiguous, not used
    twice = (("int", enc), ("int", len(LEAD_FLAG)), ("int", 5), None,
             ("int", enc), ("int", len(LEAD_FLAG)), ("int", 6), None)
    assert dd._align(m, s.args, twice, 4) is None
    # ... while one agreeing shift among contradicting ones is used
    once = (("int", enc), ("int", len(LEAD_FLAG)), ("int", enc), ("int", len(LEAD_FLAG)), ("int", 7), None)
    assert dd._align(m, s.args, once, 4)[2] == ("int", 7)


def test_align_uses_position_only_when_the_site_binds_nothing_and_the_arity_matches():
    m = model("dd_lead_x86_64")
    blank = (None, None, None, None, None, None)
    assert dd._align(m, blank, (("int", 1), ("int", 2)), 2) == (("int", 1), ("int", 2))
    assert dd._align(m, blank, (("int", 1), ("int", 2), ("int", 3)), 2) is None


def test_agree_compares_integers_pointers_and_strings():
    m = model("dd_flag_x86_64")
    enc = site(m, "main", "dd_xor_decode").args[0][1]
    assert dd._agree(m, ("int", 0xFFFFFFFF), ("int", M64)) == 1        # -1 printed for a 32-bit register
    assert dd._agree(m, ("int", 5), ("int", 6)) == -1
    assert dd._agree(m, ("int", 5), None) == 0 and dd._agree(m, None, ("int", 5)) == 0
    assert dd._agree(m, ("ptr", enc), ("int", enc)) == 1
    assert dd._agree(m, ("ptr", enc), ("int", enc + 0x100000)) == 1    # Ghidra's PIE base
    assert dd._agree(m, ("ptr", enc), ("int", enc + 1)) == -1
    assert dd._agree(m, ("ptr", enc), ("ptr", enc)) == 1
    assert dd._agree(m, ("ptr", enc), ("bytes", m_enc(FLAG, 0x5A)[:8])) == 1
    assert dd._agree(m, ("ptr", enc), ("bytes", b"nope")) == -1
    assert dd._agree(m, ("stk", ("rsp", 0)), ("int", 1)) == -1
    assert dd._agree(m, ("int", 5), ("bytes", b"5")) == -1


R2_MAIN = '''
void main(int argc,char **argv,char **envp)

{
    ulong noname_0;
    double in_XMM1_Qa;
    uchar auStack_58 [64];

    noname_0 = loc.imp.puts("decoding");
    %(callee)s(noname_0,in_XMM1_Qa,0x%(enc)x,0x1d,0x5a,auStack_58);
    loc.imp.puts(auStack_58);
    return;
}
'''


def _write_pseudo(root: Path, text: str, name: str = "main.c") -> Path:
    d = dd.decompile_dir(root, "files/chal")
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(text)
    return d


def test_decompile_dir_is_where_b011_writes():
    import decompile_intake as di
    assert dd.decompile_dir(Path("/c"), "files/a b/x.bin") == \
        Path("/c") / "recon" / "decompile" / di._safe("files/a b/x.bin".replace("/", "__"))


@needs_unicorn
@pytest.mark.parametrize("name,callee", [("dd_lead_x86_64", "sym.dd_keyed"),
                                         ("dd_lead_x86_64_stripped", "fcn.%08x")])
def test_a_decompile_lead_binds_the_argument_the_call_site_could_not(tmp_path, name, callee):
    root = challenge(tmp_path, name)
    before = dd.solve(root, CSCTF)
    assert before.status == "unsure" and before.flags == ()
    assert any("declined" in d for d in details(before, "decoder-candidate"))
    full = model("dd_lead_x86_64")
    s = site(full, "main", "dd_keyed")
    if "%" in callee:
        callee = callee % fn(full, "dd_keyed").addr
    _write_pseudo(root, R2_MAIN % dict(callee=callee, enc=s.args[0][1]))
    after = dd.solve(root, CSCTF)
    assert after.status == "candidate" and after.flags == (LEAD_FLAG.decode(),)
    assert any("completed by decompile lead main.c" in d and repr(LEAD_FLAG.decode()) in d
               for d in details(after, "emulate"))
    assert [e.path for e in after.evidence if e.kind == "decompile"] == ["recon/decompile/files__chal"]


@needs_unicorn
def test_a_lead_can_name_a_function_the_scan_did_not_find(tmp_path, monkeypatch):
    full = model("dd_lead_x86_64")
    orphan = fn(full, "dd_orphan").addr
    assert model("dd_lead_x86_64_stripped").funcs[orphan].sources == {"gap"}    # the start scan finds it ...
    monkeypatch.setattr(dd, "SCAN_GAPS", False)            # ... so turn it off to stand for a start it misses
    bare = dd.analyse(blob("dd_lead_x86_64_stripped"))
    assert orphan not in bare.funcs                       # nothing calls it and the image is stripped
    root = challenge(tmp_path, "dd_lead_x86_64_stripped")
    _write_pseudo(root, "void entry0(void)\n{\n    fcn.%08x(7);\n}\n" % orphan, "entry0.c")
    result = dd.solve(root, CSCTF)
    line = [d for d in details(result, "emulate") if "fcn.%08x@" % orphan in d]
    assert line and "(0x7) [decompile lead entry0.c]" in line[0] and "return %#x" % m_orphan(7) in line[0]
    # and the lead alone is refused when its argument count is not the function's arity
    again = dd.analyse(blob("dd_lead_x86_64_stripped"), extra={orphan})
    f = again.funcs[orphan]
    assert f.arity == 1 and "decompile" in f.sources
    bad = [dd.Lead(orphan, (("int", 7), ("int", 8)), "entry0.c")]
    assert [b for b in dd._bindings(again, f, bad)[0] if not b.open] == []


def test_pseudocode_bounds_are_reported(tmp_path, monkeypatch):
    root = challenge(tmp_path, "dd_flag_x86_64")
    m = model("dd_flag_x86_64")
    d = _write_pseudo(root, "sym.dd_mix(1);\n" * 5)
    (d / "notes.txt").write_text("sym.dd_mix(2);")                 # not a .c file: not read
    monkeypatch.setattr(dd, "MAX_LEADS", 3)
    leads, notes = dd.decompile_leads(m, root, "files/chal")
    assert len(leads) == 3 and any("more than 3 decompiled calls" in n for n in notes)
    monkeypatch.setattr(dd, "MAX_LEADS", 256)
    monkeypatch.setattr(dd, "MAX_LEAD_BYTES", 20)
    leads, notes = dd.decompile_leads(m, root, "files/chal")
    assert len(leads) == 1 and any("main.c read to 20 bytes only" in n for n in notes)
    monkeypatch.setattr(dd, "MAX_LEAD_FILES", 0)
    leads, notes = dd.decompile_leads(m, root, "files/chal")
    assert leads == [] and any("1 more pseudocode file(s) not read" in n for n in notes)
    assert dd.decompile_leads(m, root, "files/other") == ([], [])  # B-011 wrote nothing for that file


@needs_unicorn
@pytest.mark.needs_tool("radare2")
def test_real_b011_pseudocode_binds_the_key_end_to_end(tmp_path):
    import decompile_intake as di
    root = challenge(tmp_path, "dd_lead_x86_64")
    assert dd.solve(root, CSCTF).status == "unsure"
    di._r2_pdg_cache.clear()
    assert di.R2GhidraBackend().available(), "radare2 lacks the r2ghidra pdg plugin"
    intake = di.solve(root, CSCTF)                           # B-011: static decompile, nothing is run
    assert (root / "recon" / "decompile" / "files__chal" / "main.c").is_file(), intake.notes
    result = dd.solve(root, CSCTF)
    assert result.status == "candidate" and result.flags == (LEAD_FLAG.decode(),), result.notes


# ================================================================== B-026 leads
def test_b026_readers_mark_the_mixer_and_the_looped_check():
    m = model("dd_flag_x86_64")
    leads = dd.check_leads(m)
    assert any("mixer function (64-bit" in r for r in leads[fn(m, "dd_mix").addr])
    assert any("looped: B-026 does not lift it" in r for r in leads[fn(m, "dd_checksum").addr])
    assert not any("mixer" in r for r in leads.get(fn(m, "dd_checksum").addr, ()))
    assert not any("looped" in r for r in leads.get(fn(m, "dd_mix").addr, ()))
    assert not any(f.stub for a, f in m.funcs.items() if a in leads)
    assert dd.check_leads(model("dd_flag_x86_64_stripped")).keys() >= {fn(m, "dd_mix").addr}


def test_only_small_straight_line_functions_are_asked_about_being_a_mixer(monkeypatch):
    import invert_checks as ic
    m = model("dd_flag_x86_64")
    asked = []
    real = ic.recognise_mixer_function

    def spy(code, **kw):
        asked.append(kw["base"])
        return real(code, **kw)

    monkeypatch.setattr(ic, "recognise_mixer_function", spy)
    dd.check_leads(m)
    assert fn(m, "dd_mix").addr in asked and fn(m, "dd_abi").addr in asked
    for name in ("dd_xor_decode", "dd_sum", "dd_checksum", "dd_round"):     # loops
        assert fn(m, name).addr not in asked
    assert fn(m, "main").addr not in asked and fn(m, "dd_len").addr not in asked   # calls
    monkeypatch.setattr(ic, "MAX_MIXER_FUNC_BYTES", 8)
    asked.clear()
    assert not any("mixer" in r for rs in dd.check_leads(m).values() for r in rs)
    assert fn(m, "dd_mix").addr not in asked


def test_b026_leads_are_x86_only():
    assert dd.check_leads(model("dd_flag_arm64")) == {}


def test_a_missing_b026_reader_is_named_not_silent(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "_CHECKS", [])
    monkeypatch.setitem(sys.modules, "invert_checks", None)
    with pytest.raises(RuntimeError, match="invert_checks"):
        dd.check_leads(model("dd_flag_x86_64"))
    result = dd.solve(challenge(tmp_path, "dd_plain_x86_64"), CSCTF)
    assert result.status == "unsure" and "B-026 leads not read" in result.notes     # never a clean "none"


# ================================================================== ranking and binding
def test_rank_puts_bound_decoders_first_and_explains_itself():
    m = model("dd_flag_x86_64")
    ranked = dd.rank(m, (), dd.check_leads(m))
    order = [c.name for c in ranked]
    for bound in ("dd_xor_decode", "dd_sum", "dd_round", "dd_mix"):
        assert order.index(bound) < order.index("dd_checksum") < order.index("main")
    by = {c.name: c for c in ranked}
    assert order[0] == "dd_xor_decode" and "1 bound call(s)" in by["dd_xor_decode"].reasons
    assert "called with an unbound argument" in by["dd_checksum"].reasons
    assert "only prints through puts (no loop, transform, byte or table access)" in by["main"].reasons
    assert not any("unmodelled" in r for r in by["main"].reasons)     # puts is captured, not unmodelled
    assert by["dd_abi"].score < dd.EVAL_MIN and by["main"].score < dd.EVAL_MIN
    assert ranked == sorted(ranked, key=lambda c: (-c.score, c.addr))
    assert all(c.func.stub is None for c in ranked)


def test_rank_scores_each_signal():
    m = model("dd_flag_x86_64")
    plain = {c.name: c for c in dd.rank(m)}
    checks = dd.check_leads(m)
    led = {c.name: c for c in dd.rank(m, (), checks)}
    assert led["dd_mix"].score - plain["dd_mix"].score == 20                   # a B-026 mixer
    assert led["dd_checksum"].score - plain["dd_checksum"].score == 10         # a B-026 check candidate
    lead = dd.Lead(fn(m, "dd_checksum").addr, (None,), "main.c")
    with_lead = {c.name: c for c in dd.rank(m, [lead])}
    assert with_lead["dd_checksum"].score - plain["dd_checksum"].score == 25   # called in B-011 pseudocode
    assert any("B-011 pseudocode (main.c)" in r for r in with_lead["dd_checksum"].reasons)
    # structure: a bound call 40, a loop 10, byte access 5, indexed access 5, a decoder-like name 15
    xd = plain["dd_xor_decode"]
    assert xd.score == 40 + 10 + min(20, 2 * xd.func.scan.transform) + 5 + 5 + 15
    assert plain["dd_first"].score == 40 + min(20, 2 * fn(m, "dd_first").scan.transform) + \
        (5 if fn(m, "dd_first").scan.byte_mem else 0)
    assert plain["main"].score == -30                                           # only the import penalty
    ck = plain["dd_checksum"]                   # called, but with a run-time argument: 15, not 40
    assert ck.score == 15 + 10 + 2 * ck.func.scan.transform + 5 + 15 and ck.func.scan.transform == 1


def test_rank_counts_machine_state_and_a_missing_return_against():
    m = model("dd_track_x86_64")
    by = {c.name: c for c in dd.rank(m)}
    assert by["tk_env"].score == -30 and "reads machine or thread state" in by["tk_env"].reasons
    assert by["tk_unary_noret"].score == 2 - 10 and "no return seen" in by["tk_unary_noret"].reasons
    assert by["tk_unary_ok"].score == 2 and by["tk_unary_ok"].reasons == ("1 transform op(s)",)


def test_rank_leaves_out_stubs_the_entry_and_constructors():
    m = model("dd_state_x86_64")
    names = {c.name for c in dd.rank(m)}
    assert "dd_init" not in names and {"dd_table_flag", "dd_unmask", "dd_poke"} <= names
    assert "ctor" in fn(m, "dd_init").sources


def test_bindings_order_and_kinds():
    m = model("dd_lead_x86_64")
    keyed, late, orphan = fn(m, "dd_keyed"), fn(m, "dd_late"), fn(m, "dd_orphan")
    (b,), why = dd._bindings(m, keyed, ())
    assert why == "" and b.open and b.args[2] == ("out", 2) and b.site == site(m, "main", "dd_keyed").addr
    assert "1 unbound argument(s) passed as output buffers" in b.source
    (b,), _ = dd._bindings(m, late, ())
    assert b.open and b.args == (("out", 0),)
    (b,), _ = dd._bindings(m, orphan, ())                      # nothing calls it: its one argument is open
    assert b.open and b.site is None and b.args == (("out", 0),)
    enc = site(m, "main", "dd_keyed").args[0][1]
    lead = dd.Lead(keyed.addr, (None, None, ("int", enc), ("int", 0x1D), ("int", 0x5A), None), "main.c")
    bound, _ = dd._bindings(m, keyed, [lead])
    assert len(bound) == 1 and not bound[0].open and bound[0].args[2] == ("int", 0x5A)   # the open one is dropped


def test_bindings_of_a_function_nothing_calls():
    m = model("dd_never_x86_64")
    (b,), _ = dd._bindings(m, fn(m, "dd_never_ret"), ())
    assert b.args == () and not b.open and b.site is None
    m2 = model("dd_track_x86_64")
    wide = dd.Func(0x9999, arity=3)
    assert dd._bindings(m2, wide, ()) == ([], "takes 3 argument(s) and no direct call to it was found")
    assert dd._bindings(m2, dd.Func(0x9999), ()) == ([], "its body was not read")


def test_a_lead_integer_that_is_a_data_address_is_also_tried_as_the_pointer():
    m = model("dd_flag_x86_64")
    enc = site(m, "main", "dd_xor_decode").args[0][1]
    assert m.is_data(enc) and not m.is_data(0x25) and not m.is_data(fn(m, "dd_mix").addr)
    assert dd._lead_variants(m, (("int", enc), ("int", 0x25))) == [(("ptr", enc), ("int", 0x25)),
                                                                    (("int", enc), ("int", 0x25))]
    assert dd._lead_variants(m, (("int", 0x25), None)) == [(("int", 0x25), None)]


# ================================================================== evaluation
@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_bound_calls_evaluate_to_the_independent_models(arch):
    m = model("dd_flag_" + arch)
    s = site(m, "main", "dd_xor_decode")
    got, out = outputs(m, "dd_xor_decode", s.args[:4])
    assert got == {"buffer": FLAG + b"\x00"} and out.engine == "native_image" and not out.stateful
    assert outputs(m, "dd_mix", (("int", 0x1337),))[0] == {"return": m_mix(0x1337)}
    assert outputs(m, "dd_round", (("int", 0x10), ("int", 3)))[0] == {"return": m_round(0x10, 3)}
    assert outputs(m, "dd_sum", s.args[:2])[0] == {"return": m_sum(m_enc(FLAG, 0x5A))}
    assert outputs(m, "dd_word", (("int", 2),))[0] == {"string": b"charlie"}
    assert outputs(m, "dd_word", (("int", 5),))[0] == {"string": b"bravo"}          # i & 3
    assert outputs(m, "dd_first", ())[0] == {"return": ord("o")}                    # through a relocated pointer
    text = site(m, "main", "dd_len").args[:1]
    assert text[0][0] == "ptr" and outputs(m, "dd_len", text)[0] == {"return": len("hello, decoder") + 1}


@needs_unicorn
def test_a_buffer_the_caller_filled_first_is_bound_with_what_it_stored():
    m = model("dd_inout_x86_64")
    s = site(m, "main", "dd_inplace")
    assert s.args[1] == ("int", 24)
    kind, key, init = s.args[0]
    assert (kind, key) == ("stk", ("rsp", 0))
    # main stores the encoded text with a constant-pool vector move, a movabs and a byte store: the scan
    # rebuilds exactly those bytes (the independent encoding, then the NUL main writes)
    assert [o for o, _b in init] == [0, 16, 24]
    assert b"".join(b for _o, b in init) == bytes(p ^ 0x42 for p in INOUT_PLAIN) + b"\x00"
    got, _ = outputs(m, "dd_inplace", s.args[:2])
    assert got == {"buffer": INOUT_PLAIN + b"\x00"}
    # without what the caller stored the same call reads undefined bytes and declines, never decoding zeros
    with pytest.raises(dd.Decline, match="undefined"):
        dd.evaluate(m, fn(m, "dd_inplace").addr, (("stk", key), s.args[1]))


@needs_unicorn
def test_a_buffer_the_call_only_reads_is_not_reported_as_output():
    m = model("dd_flag_x86_64")
    filled = ("stk", ("rsp", 0), ((0, b"abc\x00"),))
    got, _ = outputs(m, "dd_checksum", (filled,))
    assert got == {"return": m_checksum(b"abc")}         # the caller's own bytes are no decoded output


@needs_unicorn
def test_one_stack_buffer_passed_twice_is_one_buffer():
    m = model("dd_inout_x86_64")
    s = site(m, "main", "dd_alias")
    assert s.args[0] == s.args[1] and s.args[0][0] == "stk"
    assert outputs(m, "dd_alias", s.args[:2])[0] == {"buffer": b"x"}
    with pytest.raises(dd.Decline, match="undefined"):          # two different buffers: b[0] was never written
        dd.evaluate(m, fn(m, "dd_alias").addr, (("out", 0), ("out", 1)))
    assert outputs(m, "dd_dup", (("int", 3),))[0] == {"string": b"heap3"}      # a string built on the heap


@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_the_load_phase_runs_and_global_writes_are_reported(arch):
    m = model("dd_state_" + arch)
    got, out = outputs(m, "dd_table_flag", ())
    assert got == {"string": STATE_FLAG, "global": STATE_FLAG} and out.stateful and not out.pristine
    s = site(m, "main", "dd_unmask")
    got, out = outputs(m, "dd_unmask", s.args[:3])
    assert got.pop("global") == STATE_BLOB + b"\x00" and out.stateful      # the table's NUL is decoded too
    assert got in ({}, {"string": STATE_BLOB})        # void: a leftover pointer to the decoded text, or nothing
    assert [o.where for o in out.outputs if o.kind == "global"] == [s.args[0][1]]


@needs_unicorn
def test_an_unbound_argument_is_an_output_buffer_or_a_decline():
    m = model("dd_never_x86_64")
    got, _ = outputs(m, "dd_never_out", (("out", 0),))
    assert got["buffer"] == NEVER_FLAG + b"\x00"
    m2 = model("dd_flag_x86_64")
    with pytest.raises(dd.Decline, match="undefined"):                      # reads through the pointer
        dd.evaluate(m2, fn(m2, "dd_checksum").addr, (("out", 0),))
    with pytest.raises(dd.Decline, match="nothing the two layouts agree on"):   # uses the pointer as a number
        dd.evaluate(m2, fn(m2, "dd_mix").addr, (("out", 0),))
    with pytest.raises(dd.Decline, match="not bound"):
        dd.evaluate(m2, fn(m2, "dd_mix").addr, (("page", 0x1000),))


@needs_unicorn
def test_a_leftover_pointer_in_the_return_register_is_not_reported_as_a_string():
    # dd_xor_decode is void: on AArch64 x0 still points at its input table when it returns
    m = model("dd_flag_arm64")
    out = dd.evaluate(m, fn(m, "dd_xor_decode").addr, site(m, "main", "dd_xor_decode").args[:4])
    assert [o.kind for o in out.outputs] == ["buffer"]


@needs_unicorn
def test_the_exact_evaluator_cross_checks_integer_calls(monkeypatch):
    m = model("dd_flag_x86_64")
    seen = []
    real = nb._fallback_x86

    def spy(img, address, argument):
        seen.append((address, list(argument)))
        return real(img, address, argument)

    monkeypatch.setattr(nb, "_fallback_x86", spy)
    assert outputs(m, "dd_mix", (("int", 0x1337),))[0] == {"return": m_mix(0x1337)}
    enc = site(m, "main", "dd_sum").args[0]
    assert outputs(m, "dd_sum", (enc, ("int", 37)))[0] == {"return": m_sum(m_enc(FLAG, 0x5A))}
    assert seen == [(fn(m, "dd_mix").addr, [0x1337]), (fn(m, "dd_sum").addr, [enc, 37])]
    # a buffer call is outside the exact evaluator: it is not consulted
    dd.evaluate(m, fn(m, "dd_xor_decode").addr, site(m, "main", "dd_xor_decode").args[:4])
    assert len(seen) == 2
    # the two evaluators disagreeing declines (64-bit and 32-bit results)
    monkeypatch.setattr(nb, "_fallback_x86", lambda img, a, arg: (m_mix(0x1337) ^ 1, None))
    with pytest.raises(dd.Decline, match="evaluators disagree"):
        dd.evaluate(m, fn(m, "dd_mix").addr, (("int", 0x1337),))
    monkeypatch.setattr(nb, "_fallback_x86", lambda img, a, arg: (0, None))
    with pytest.raises(dd.Decline, match="evaluators disagree"):
        dd.evaluate(m, fn(m, "dd_sum").addr, (enc, ("int", 37)))


@needs_unicorn
def test_the_exact_evaluator_is_not_consulted_for_an_image_with_constructors(monkeypatch):
    m = model("dd_state_x86_64")
    monkeypatch.setattr(nb, "_fallback_x86", lambda *a: pytest.fail("the exact evaluator runs no constructor"))
    assert outputs(m, "dd_table_flag", ())[0]["string"] == STATE_FLAG


def test_with_unicorn_guarded_off_the_exact_evaluator_stands_in(monkeypatch):
    monkeypatch.setattr(ni, "UNICORN_AVAILABLE", False)
    m = model("dd_flag_x86_64")
    got, out = outputs(m, "dd_mix", (("int", 0x1337),))
    assert got == {"return": m_mix(0x1337)} and out.engine == "bounded_x86" and not out.pristine
    assert outputs(m, "dd_round", (("int", 0x10), ("int", 3)))[0] == {"return": m_round(0x10, 3)}
    enc = site(m, "main", "dd_sum").args[0]
    assert outputs(m, "dd_sum", (enc, ("int", 37)))[0] == {"return": m_sum(m_enc(FLAG, 0x5A))}
    with pytest.raises(dd.Decline, match="unicorn engine not available"):          # a buffer call
        dd.evaluate(m, fn(m, "dd_xor_decode").addr, site(m, "main", "dd_xor_decode").args[:4])
    with pytest.raises(dd.Decline, match="unicorn engine not available"):          # a relocated read
        dd.evaluate(m, fn(m, "dd_first").addr, ())
    arm = model("dd_flag_arm64")
    with pytest.raises(dd.Decline, match="unicorn engine not available"):          # no AArch64 evaluator
        dd.evaluate(arm, fn(arm, "dd_mix").addr, (("int", 0x1337),))


@needs_unicorn
def test_any_other_emulator_decline_is_never_bypassed(monkeypatch):
    m = model("dd_flag_x86_64")
    monkeypatch.setattr(nb, "_fallback_x86", lambda img, a, arg: (123, None))
    with pytest.raises(dd.Decline, match="budget"):
        dd.evaluate(m, fn(m, "dd_round").addr, (("int", 0x10), ("int", 3)), max_blocks=1)


@needs_unicorn
def test_a_static_image_is_read_pristine_and_says_so(monkeypatch):
    m = model("dd_flag_x86_64")
    calls = []
    real = ni.emulate_call

    def static_image(data, addr, args, **kw):
        calls.append(kw["init"])
        if kw["init"] == "auto":
            raise ni.EmulationError("a static image's constructor table is not modelled")
        return real(data, addr, args, **kw)

    monkeypatch.setattr(ni, "emulate_call", static_image)
    got, out = outputs(m, "dd_mix", (("int", 0x1337),))
    assert got == {"return": m_mix(0x1337)} and out.pristine and calls == ["auto", "skip"]
    monkeypatch.setattr(ni, "emulate_call", lambda *a, **kw: (_ for _ in ()).throw(ni.EmulationError("other")))
    with pytest.raises(dd.Decline, match="other"):
        dd.evaluate(m, fn(m, "dd_mix").addr, (("int", 0x1337),))


# ================================================================== the exact evaluator (native_behavior)
def test_fallback_takes_several_integer_and_pointer_arguments():
    m = model("dd_flag_x86_64")
    assert nb._fallback_x86(m.img, fn(m, "dd_round").addr, [0x10, 3])[0] == m_round(0x10, 3)
    assert nb._fallback_x86(m.img, fn(m, "dd_round").addr, [0x10, 0])[0] == 0x10
    enc = site(m, "main", "dd_sum").args[0]
    assert nb._fallback_x86(m.img, fn(m, "dd_sum").addr, [enc, 37])[0] == m_sum(m_enc(FLAG, 0x5A))
    assert nb._fallback_x86(m.img, fn(m, "dd_mix").addr, 0x1337)[0] == m_mix(0x1337)       # the old call shape
    with pytest.raises(nb.Decline, match="more than six"):
        nb._fallback_x86(m.img, fn(m, "dd_mix").addr, [1] * 7)
    with pytest.raises(nb.Decline, match="unsupported argument kind"):
        nb._fallback_x86(m.img, fn(m, "dd_mix").addr, [("stk", 0)])
    with pytest.raises(nb.Decline):                         # the second argument is read but was never given
        nb._fallback_x86(m.img, fn(m, "dd_round").addr, [0x10])


def test_fallback_follows_an_internal_call_in_both_layouts():
    m = model("dd_track_x86_64")
    value, run = nb._fallback_x86(m.img, fn(m, "tk_wrap").addr, [5, 6])      # tk_sink(5, 6, 1)
    assert value == 12 and run.calls == 1


def test_fallback_layouts_load_a_position_independent_image_at_two_addresses():
    m = model("dd_flag_x86_64")
    word = fn(m, "dd_word").addr
    # dd_word returns a pointer into the image: one layout alone computes "a value", two disagree
    one = nb._Eval(m.img, [2], 0x700012345008, 0).run(word)[0]
    two = nb._Eval(m.img, [2], 0x700012345008, nb._FALLBACK_BIAS).run(word)[0]
    assert two - one == nb._FALLBACK_BIAS and m.img.file_bytes(one, 8) == b"charlie\x00"
    with pytest.raises(nb.Decline, match="layouts disagree"):
        nb._fallback_x86(m.img, word, [2])
    # the recorded trace is in image addresses whatever the layout
    a = nb._Eval(m.img, [0x1337], 0x700012345008, 0)
    b = nb._Eval(m.img, [0x1337], 0x700012345008, nb._FALLBACK_BIAS)
    a.run(fn(m, "dd_mix").addr)
    b.run(fn(m, "dd_mix").addr)
    assert a.trace == b.trace and a.trace[0][0] == fn(m, "dd_mix").addr


def test_fallback_never_reads_a_slot_the_loader_relocates():
    m = model("dd_flag_x86_64")
    assert m.img.plan                                           # the image has relocations
    with pytest.raises(nb.Decline, match="relocates"):
        nb._fallback_x86(m.img, fn(m, "dd_first").addr, [])
    slot = min(off for off, _kind, _payload in m.img.plan)
    ev = nb._Eval(m.img, [], 0x700012345008)
    for addr, n in ((slot, 8), (slot + 3, 1), (slot + 7, 1), (slot - 4, 8)):     # any byte of the slot
        with pytest.raises(nb.Decline, match="relocates"):
            ev._read_mem(addr, n)


# ================================================================== native_behavior: discovered targets
QUESTION = ("Recover the value the decoder routine returns when called with seed %s: submit the %d-byte result, "
            "little-endian, as lowercase hex.")


def q(seed, width):
    return {"id": "q1", "question": QUESTION % (seed, width)}


@needs_unicorn
@pytest.mark.parametrize("name", ["dd_flag_x86_64", "dd_flag_arm64", "dd_flag_x86_64_stripped"])
def test_the_question_path_finds_a_decoder_the_entry_does_not_call(name, tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    data = blob(name)
    full = model("dd_flag_arm64" if "arm64" in name else "dd_flag_x86_64")
    spec = nb.contract(q("0x1337", 8))
    assert spec == nb.Contract(0x1337, 8, "little", None)
    img, rows = nb.discover(data, spec)
    assert rows == [(fn(full, "dd_mix").addr, site(full, "main", "dd_mix").addr)]
    answer = nb.answer(q("0x1337", 8), data)
    payload = json.loads(answer[answer.index("{"):])
    assert payload["o"] == [["entry_call_return_lower_hex", m_mix(0x1337).to_bytes(8, "little").hex()]]
    assert payload["k"].startswith("binary.native_behavior/elf+scope_sha256_")


@needs_unicorn
def test_the_question_path_declines_when_two_bound_targets_disagree(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    m = model("dd_decoy_x86_64")
    data = blob("dd_decoy_x86_64")
    img, rows = nb.discover(data, nb.contract(q("0x77", 8)))
    assert {t for t, _s in rows} == {fn(m, "dd_twin_a").addr, fn(m, "dd_twin_b").addr}
    assert nb.evaluate(data, img, fn(m, "dd_twin_a").addr, 0x77)[0] == m_twin_a(0x77)
    assert nb.evaluate(data, img, fn(m, "dd_twin_b").addr, 0x77)[0] == m_twin_b(0x77)
    assert m_twin_a(0x77) != m_twin_b(0x77)
    assert nb.answer(q("0x77", 8), data) is None


@needs_unicorn
@pytest.mark.parametrize("name,gaps", [("dd_lead_x86_64", True), ("dd_lead_x86_64_stripped", True),
                                       ("dd_lead_x86_64_stripped", False)])
def test_with_no_call_binding_the_argument_the_one_argument_decoders_are_the_targets(name, gaps, tmp_path,
                                                                                     monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(dd, "SCAN_GAPS", gaps)
    full = model("dd_lead_x86_64")
    data = blob(name)
    img, rows = nb.discover(data, nb.contract(q("0x2a", 4)))
    want = [(fn(full, "dd_late").addr, None)]
    if gaps:
        # the symbol table, or in the stripped image the function-start scan, names the uncalled one too
        want.append((fn(full, "dd_orphan").addr, None))
    assert rows == want
    answer = nb.answer(q("0x2a", 4), data)
    if not gaps:
        payload = json.loads(answer[answer.index("{"):])
        assert payload["o"] == [["entry_call_return_lower_hex", m_late(0x2A).to_bytes(4, "little").hex()]]
    else:
        assert m_late(0x2A) != m_orphan(0x2A) and answer is None     # two plausible decoders that differ


@needs_unicorn
def test_a_plausible_target_that_cannot_be_proved_declines_the_answer(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    m = model("dd_flag_x86_64")
    data = blob("dd_flag_x86_64")
    img, rows = nb.discover(data, nb.contract(q("0x4242", 8)))       # no call passes 0x4242
    assert rows == [(fn(m, "dd_mix").addr, None), (fn(m, "dd_checksum").addr, None)]
    assert nb.evaluate(data, img, fn(m, "dd_mix").addr, 0x4242)[0] == m_mix(0x4242)
    assert nb.answer(q("0x4242", 8), data) is None                   # dd_checksum(0x4242) cannot be evaluated


def test_unary_rows_keep_only_functions_that_could_be_the_decoder():
    m = model("dd_track_x86_64")
    # of the one-argument functions only tk_unary_ok returns, transforms, calls nothing unmodelled or
    # indirect, reads no machine state and was read completely
    one_arg = {f.name for f in m.funcs.values() if f.arity == 1}
    assert one_arg == {"tk_unary_ok", "tk_unary_env", "tk_unary_ind", "tk_unary_imp", "tk_unary_noret",
                       "tk_unary_trunc", "tk_only"}
    assert dd.unary_rows(m, 0x999) == [(fn(m, "tk_unary_ok").addr, None)]


def test_unary_rows_skip_calls_that_pass_more_than_the_stated_argument():
    m = model("dd_flag_x86_64")
    assert dd.unary_rows(m, 0x10) == dd.unary_rows(m, 0x4242)        # dd_round(0x10, 3) takes two arguments
    assert dd.unary_rows(m, 2) == [(fn(m, "dd_word").addr, site(m, "main", "dd_word").addr)]
    assert dd.unary_rows(m.img, 0x1337) == [(fn(m, "dd_mix").addr, site(m, "main", "dd_mix").addr)]


def test_the_entry_point_binding_still_comes_first(monkeypatch):
    m = model("dd_flag_x86_64")
    data = bytearray(blob("dd_flag_x86_64"))
    data[24:32] = fn(m, "main").addr.to_bytes(8, "little")           # make main the ELF entry point
    monkeypatch.setattr(nb, "_discovered", lambda *a: pytest.fail("the entry binds the argument itself"))
    img, rows = nb.discover(bytes(data), nb.Contract(0x1337, 8, "little"))
    assert rows == [(fn(m, "dd_mix").addr, site(m, "main", "dd_mix").addr)]


def test_discovery_being_unavailable_is_a_decline_with_the_reason(monkeypatch):
    monkeypatch.setitem(sys.modules, "decoder_discovery", None)
    with pytest.raises(nb.Decline, match="decoder_discovery is unavailable"):
        nb.discover(blob("dd_flag_x86_64"), nb.Contract(0x1337, 8, "little"))


def test_the_question_path_with_unicorn_off(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(ni, "UNICORN_AVAILABLE", False)
    data = blob("dd_flag_x86_64")
    m = model("dd_flag_x86_64")
    img, rows = nb.discover(data, nb.contract(q("0x1337", 8)))
    value, _trace, engine = nb.evaluate(data, img, rows[0][0], 0x1337)
    assert (value, engine) == (m_mix(0x1337), "bounded_x86") and rows[0][0] == fn(m, "dd_mix").addr
    answer = nb.answer(q("0x1337", 8), data)
    assert m_mix(0x1337).to_bytes(8, "little").hex() in answer
    assert nb.answer(q("0x1337", 8), blob("dd_flag_arm64")) is None      # no AArch64 stand-in


# ================================================================== the engine entry
@needs_unicorn
@pytest.mark.parametrize("name,flag", [
    ("dd_flag_x86_64", FLAG), ("dd_flag_arm64", FLAG), ("dd_flag_x86_64_stripped", FLAG),
    ("dd_state_x86_64", STATE_FLAG), ("dd_state_arm64", STATE_FLAG),
    ("dd_never_x86_64", NEVER_FLAG), ("dd_never_arm64", NEVER_FLAG)])
def test_solve_decodes_the_flag_with_no_model(tmp_path, name, flag):
    result = dd.solve(challenge(tmp_path, name), CSCTF)
    assert isinstance(result, SolverResult) and result.engine == "binary.decoder_discovery"
    assert result.status == "candidate" and result.flags == (flag.decode(),), result.notes
    hits = [d for d in details(result, "emulate") if repr(flag.decode()) in d]
    assert hits and all(e.path == "files/chal" for e in result.evidence)
    assert "via native_image" in hits[0] and flag.decode() in result.notes
    assert ("B-026 leads cover i386/amd64 only" in result.notes) == name.endswith("arm64")


@needs_unicorn
def test_solve_says_how_each_output_was_bound(tmp_path):
    result = dd.solve(challenge(tmp_path, "dd_flag_x86_64"), CSCTF)
    lines = details(result, "emulate")
    m = model("dd_flag_x86_64")
    assert any("dd_mix@%#x(0x1337) [call site %#x] -> return %#x via native_image"
               % (fn(m, "dd_mix").addr, site(m, "main", "dd_mix").addr, m_mix(0x1337)) in d for d in lines)
    assert any("stack-buffer) [call site" in d and "buffer" in d for d in lines)
    assert any("-> string 'charlie'" in d for d in lines)
    assert any("dd_checksum" in d and "declined: read of undefined memory" in d
               for d in details(result, "decoder-candidate"))
    never = dd.solve(challenge(tmp_path / "n", "dd_never_x86_64"), CSCTF)
    assert any("[no call site: its 1 argument(s) passed as output buffers]" in d for d in details(never, "emulate"))
    assert not any("-> string '<'" in d for d in details(never, "emulate"))     # a 1-byte leftover is no string
    assert any("first call after load" in d for d in details(never, "emulate"))


@needs_unicorn
def test_solve_asserts_no_flag_when_the_decoders_disagree(tmp_path):
    result = dd.solve(challenge(tmp_path, "dd_decoy_x86_64"), CSCTF)
    assert result.status == "unsure" and result.flags == ()
    assert "the decoders disagree: 2 different flag-format values, none asserted" in result.notes
    shown = "\n".join(details(result, "emulate"))
    assert DECOY_A in shown and DECOY_B in shown


@needs_unicorn
def test_solve_reports_outputs_that_are_not_a_flag_and_candidates_it_could_not_evaluate(tmp_path):
    result = dd.solve(challenge(tmp_path, "dd_inout_x86_64"), CSCTF)
    assert result.status == "unsure" and result.flags == ()
    assert "no output is in the flag format" in result.notes
    assert not any("BBBB" in e.detail for e in result.evidence)        # zeros ^ 0x42: never decoded from nothing
    assert any("dd_inplace" in d and "(stack-buffer[25 byte(s) stored], 0x18)" in d
               and "-> buffer %r" % INOUT_PLAIN.decode() in d for d in details(result, "emulate"))
    assert any("dd_addr" in d and "declined" in d for d in details(result, "decoder-candidate"))
    lead_only = dd.solve(challenge(tmp_path / "l", "dd_lead_x86_64"), CSCTF)
    assert lead_only.status == "unsure" and details(lead_only, "emulate") == []
    assert "no decoder was evaluated to an output" in lead_only.notes
    assert len(details(lead_only, "decoder-candidate")) == 4
    # main prints (captured) and reads argv: it is tried, and declines on the argv it was never given
    assert any("main@" in d and "declined: read of undefined memory" in d
               for d in details(lead_only, "decoder-candidate"))


def test_solve_none_only_when_nothing_decoder_like_exists(tmp_path):
    empty = tmp_path / "empty"
    (empty / "files").mkdir(parents=True)
    (empty / "files" / "readme.txt").write_text("no binary here")
    result = dd.solve(empty, CSCTF)
    assert (result.status, result.notes) == ("none", "no ELF binary in the handout")
    plain = dd.solve(challenge(tmp_path / "p", "dd_plain_x86_64"), CSCTF)
    assert plain.status == "none" and plain.evidence == ()
    # dd_show is called with a constant, but it only prints through an unmodelled import: it is neither
    # emulated nor a lead
    m = model("dd_plain_x86_64")
    show = {c.name: c for c in dd.rank(m)}["dd_show"]
    assert show.bindings[0].args == (("int", 1),) and show.func.scan.imports == ["puts"] and show.score < dd.LEAD_MIN
    assert plain.notes == "every handout ELF was analysed; no decoder candidate was found"


def test_solve_skips_intake_output_folders_and_symlinks(tmp_path):
    root = tmp_path
    for sub in ("recon", "unpacked"):
        (root / sub).mkdir()
        shutil.copy(FIX / "dd_flag_x86_64.so", root / sub / "chal")
    (root / "files").mkdir()
    (root / "files" / "link").symlink_to(FIX / "dd_flag_x86_64.so")
    assert dd.solve(root, CSCTF).notes == "no ELF binary in the handout"
    assert dd._handout_elfs(root) == ([], 0)
    shutil.copy(FIX / "dd_plain_x86_64.so", root / "top.bin")           # the challenge root is walked too
    assert [p.name for p in dd._handout_elfs(root)[0]] == ["top.bin"]


def test_solve_is_blocked_when_no_elf_loads_and_names_each_skip(tmp_path, monkeypatch):
    files = tmp_path / "files"
    files.mkdir()
    (files / "a32").write_bytes(b"\x7fELF\x01\x01" + b"\x00" * 100)        # ELF32: not emulated
    result = dd.solve(tmp_path, CSCTF)
    assert result.status == "blocked"
    assert "no handout ELF could be loaded: files/a32: not loaded (only ELF64 little-endian" in result.notes
    monkeypatch.setattr(dd, "MAX_ELF_BYTES", 16)
    assert "files/a32: larger than 16 bytes, not loaded" in dd.solve(tmp_path, CSCTF).notes


@needs_unicorn
def test_a_skipped_file_beside_a_decoded_one_is_named(tmp_path):
    root = challenge(tmp_path, "dd_flag_x86_64")
    (root / "files" / "broken").write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 100)
    result = dd.solve(root, CSCTF)
    assert result.status == "candidate" and "incomplete: files/broken: not loaded" in result.notes


def test_solve_is_blocked_with_the_reason_when_a_dependency_is_missing(tmp_path, monkeypatch):
    root = challenge(tmp_path, "dd_flag_x86_64")
    monkeypatch.setitem(sys.modules, "capstone", None)
    result = dd.solve(root, CSCTF)
    assert result.status == "blocked" and "capstone" in result.notes and result.flags == ()
    monkeypatch.undo()
    monkeypatch.setattr(dd, "_NATIVE", [])
    monkeypatch.setitem(sys.modules, "native_image", None)
    result = dd.solve(root, CSCTF)
    assert result.status == "blocked" and "native_image" in result.notes


def test_solve_is_blocked_when_unicorn_is_off_and_nothing_else_can_evaluate(tmp_path, monkeypatch):
    monkeypatch.setattr(ni, "UNICORN_AVAILABLE", False)
    result = dd.solve(challenge(tmp_path, "dd_inout_x86_64"), CSCTF)
    assert result.status == "blocked" and "Unicorn is off on this host" in result.notes
    assert "5 bound decoder call(s) could not be emulated" in result.notes
    # main is one of them: it prints (puts, captured) and stores a byte, so it is tried with no arguments
    assert any("main@" in d and "[no arguments" in d for d in details(result, "decoder-candidate"))
    # where the exact evaluator covers some calls their outputs are still reported
    partial = dd.solve(challenge(tmp_path / "f", "dd_flag_x86_64"), CSCTF)
    assert partial.status == "unsure" and partial.flags == ()
    assert any("return %#x via bounded_x86" % m_mix(0x1337) in d for d in details(partial, "emulate"))
    assert any("dd_xor_decode" in d and "unicorn engine not available" in d
               for d in details(partial, "decoder-candidate"))


@needs_unicorn
def test_solve_budgets_are_work_not_time(tmp_path):
    root = challenge(tmp_path, "dd_flag_x86_64")
    capped = dd.solve(root, CSCTF, max_evals="1")                     # --opt max_evals=1 arrives as text
    assert capped.status == "candidate" and len(details(capped, "emulate")) == 1
    assert "evaluation cap of 1 call(s) reached" in capped.notes
    starved = dd.solve(root, CSCTF, max_blocks=1)
    assert starved.status == "unsure" and starved.flags == ()
    assert any("budget" in d for d in details(starved, "decoder-candidate"))
    with pytest.raises(ValueError):
        dd.solve(root, CSCTF, max_blocks=0)
    with pytest.raises(ValueError):
        dd.solve(root, CSCTF, max_evals=-1)


@needs_unicorn
def test_solve_caps_the_files_and_the_bindings(tmp_path, monkeypatch):
    root = challenge(tmp_path, "dd_plain_x86_64", "dd_flag_x86_64", "dd_plain_x86_64")
    monkeypatch.setattr(dd, "MAX_ELF_FILES", 2)
    result = dd.solve(root, CSCTF)                                    # chal, chal1 tried; chal2 named
    assert result.status == "candidate" and "1 more ELF file(s) beyond the cap of 2 not tried" in result.notes
    assert {e.path for e in result.evidence} == {"files/chal1"}
    monkeypatch.setattr(dd, "MAX_ELF_FILES", 8)
    monkeypatch.setattr(dd, "MAX_BINDINGS", 0)
    none_run = dd.solve(root, CSCTF)
    assert none_run.status == "unsure" and "more bound call(s) not evaluated" in none_run.notes


def test_an_analysis_bound_makes_the_result_unsure_not_none(tmp_path, monkeypatch):
    root = challenge(tmp_path, "dd_plain_x86_64")
    assert dd.solve(root, CSCTF).status == "none"
    monkeypatch.setattr(dd, "MAX_SCAN_INSNS", 3)
    result = dd.solve(root, CSCTF)
    assert result.status == "unsure" and "files/chal: function bodies beyond 3 instructions were not read" in result.notes


def test_analysis_bounds_are_named(monkeypatch):
    monkeypatch.setattr(dd, "MAX_SCAN_INSNS", 10)
    m = dd.analyse(blob("dd_flag_x86_64"))
    assert any("beyond 10 instructions were not read" in n for n in m.notes)
    assert any(f.scan is None and f.arity is None for f in m.funcs.values() if f.stub is None)
    monkeypatch.setattr(dd, "MAX_SCAN_INSNS", 400_000)
    monkeypatch.setattr(dd, "MAX_FUNCS", 3)
    m = dd.analyse(blob("dd_flag_x86_64"))
    assert len(m.funcs) == 3 and any("more than 3 function starts" in n for n in m.notes)
    monkeypatch.setattr(dd, "MAX_FUNCS", 8192)
    monkeypatch.setattr(dd, "MAX_SWEEP_BYTES", 64)
    m = dd.analyse(blob("dd_flag_x86_64_stripped"))
    assert any("beyond 64 were not swept" in n for n in m.notes)
    monkeypatch.setattr(dd, "MAX_FUNC_BYTES", 16)
    m = dd.analyse(blob("dd_flag_x86_64"))
    assert fn(m, "dd_xor_decode").scan.truncated and not fn(m, "dd_abi").scan.truncated
    long_ones = sum(1 for f in m.funcs.values() if f.stub is None and f.end - f.addr > 16)
    assert long_ones >= 5
    assert any(n.startswith("%d function body(ies) longer than 16 bytes were read in part" % long_ones) for n in m.notes)
    monkeypatch.undo()          # the caps back to their defaults before model() builds (and caches) its model
    assert dd.MAX_FUNC_BYTES != 16
    assert not any("read in part" in n for n in model("dd_flag_x86_64").notes)       # the default cap: nothing cut


def test_the_b026_function_cap_is_named(monkeypatch):
    monkeypatch.setattr(dd, "MAX_CHECK_FUNCS", 2)
    m = dd.analyse(blob("dd_flag_x86_64"))
    total = sum(1 for f in m.funcs.values() if f.stub is None)
    leads = dd.check_leads(m)
    first_two = sorted(a for a, f in m.funcs.items() if f.stub is None)[:2]
    assert set(leads) <= set(first_two) and fn(m, "dd_mix").addr not in leads
    assert m.notes == ["B-026's readers saw the first 2 of %d functions" % total]
    dd.check_leads(m)
    assert len(m.notes) == 1                                 # said once


@needs_unicorn
def test_the_evaluation_cap_is_per_image(tmp_path):
    root = challenge(tmp_path, "dd_flag_x86_64", "dd_state_x86_64")
    result = dd.solve(root, CSCTF, max_evals=1)
    assert result.status == "candidate" and result.flags == (FLAG.decode(),)     # dd_state's first call is dd_unmask
    assert {e.path for e in result.evidence if e.kind == "emulate"} == {"files/chal", "files/chal1"}
    for rel in ("files/chal", "files/chal1"):
        assert "%s: evaluation cap of 1 call(s) reached" % rel in result.notes


# ================================================================== wiring
def test_manifest_is_valid_and_entry_resolves():
    m = _manifest.load(ROOT / "solvers" / "binary" / "decoder_discovery.manifest.toml")
    assert m.id == "binary.decoder_discovery" and m.lane == "binary"
    assert m.entry.target_file(ROOT).name == "decoder_discovery.py"
    assert m.capabilities[0] == "analysis" and m.cost_class == "medium"
    assert any(r.category == ["reverse"] or tuple(r.category or ()) == ("reverse",) for r in m.routes)


def test_engine_is_routed_and_in_the_generated_route_table():
    table = (ROOT / "ctf" / "engines" / "route_table.jsonl").read_text()
    assert '"binary.decoder_discovery"' in table
    hits = _router.route("reverse", "the flag is built by a hidden function that is never called")
    assert hits[0].manifest.id == "binary.decoder_discovery" if hasattr(hits[0], "manifest") else \
        "binary.decoder_discovery" in str(hits[0])


@needs_unicorn
def test_ctf_run_runs_the_engine_in_its_own_interpreter(tmp_path, monkeypatch):
    root = challenge(tmp_path / "c", "dd_flag_x86_64_stripped")
    monkeypatch.setenv("CTF_ENGINE_LEDGER", "0")
    cmd = _runner.command("binary.decoder_discovery", [str(root), "--event", "csctf", "--opt", "max_evals=4"],
                          record=False)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr[-2000:]
    result = SolverResult.from_json(proc.stdout.strip().splitlines()[-1])
    assert result.status == "candidate" and result.flags == (FLAG.decode(),)
    assert result.engine == "binary.decoder_discovery"


@needs_unicorn
@pytest.mark.needs_tool("clang")
def test_freshly_built_fixtures_decode_too(tmp_path):
    import decoder_discovery_fixtures as fx
    out = tmp_path / "built"
    made = {p.name for p in fx.build(out)}
    assert made == {p.name for p in FIX.glob("*.so")}                 # the committed set is the builder's set
    assert (out / "SOURCES.c").read_text() == (FIX / "SOURCES.c").read_text()
    assert (out / "SOURCES.s").read_text() == (FIX / "SOURCES.s").read_text()
    for name, flag in (("dd_flag_x86_64", FLAG), ("dd_flag_arm64", FLAG), ("dd_state_x86_64", STATE_FLAG)):
        root = tmp_path / name
        (root / "files").mkdir(parents=True)
        shutil.copy(out / (name + ".so"), root / "files" / "chal")
        result = dd.solve(root, CSCTF)
        assert result.status == "candidate" and result.flags == (flag.decode(),), (name, result.notes)


# ================================================================== fix round 1: a buffer the caller filled
def test_x86_tracker_rebuilds_what_a_stack_buffer_holds_at_the_call():
    m = model("dd_track_x86_64")
    first, second = site(m, "tk_vec", "tk_sink", 0), site(m, "tk_vec", "tk_sink", 1)
    vconst = b"sixteen byte str"
    # a constant-pool vector load stored, a zeroed register stored, a byte store; the pointer stored at
    # +40 is an address (it differs per layout) and is left undefined
    assert first.args[0] == ("stk", ("rsp", 0), ((0, vconst), (16, bytes(16)), (32, b"!")))
    assert first.args[1:3] == (("int", 1), ("int", 2))
    # after a call every vector register (and every frame slot) is forgotten
    assert second.args[0] == ("stk", ("rsp", 0))


def _rodata(m, needle):
    """The vaddr of ``needle`` in the image's file-backed bytes (exactly one place)."""
    hits = []
    for va, _memsz, filesz, off, _flags in m.img.loads:
        at = m.img.data.find(needle, off, off + filesz)
        if at >= 0:
            hits.append(va + at - off)
    assert len(hits) == 1, hits
    return hits[0]


def test_x86_tracker_forgets_vector_registers_at_branch_targets_jumps_and_other_writes():
    m = model("dd_track_x86_64")
    a, b = site(m, "tk_vec_flow", "tk_sink", 0), site(m, "tk_vec_flow", "tk_sink", 1)
    assert a.args[0] == ("stk", ("rsp", 0))              # stored after a branch target: xmm0 unknown
    assert b.args[0] == ("stk", ("rsp", 0))              # stored after an indirect jump: xmm0 unknown
    # paddb changed xmm0; xmm1 was loaded from writable .data, which a program can change: neither is known
    assert site(m, "tk_vec_clobber", "tk_sink").args[0] == ("stk", ("rsp", 0))


def test_x86_tracker_keeps_only_stores_inside_the_buffer_window_and_on_its_frame_register():
    m = model("dd_track_x86_64")
    first, second = site(m, "tk_vec_far", "tk_sink", 0), site(m, "tk_vec_far", "tk_sink", 1)
    # [rsp+0xffc] (8 bytes) runs past the OUT_SIZE window the callee is handed: left out
    assert dd.OUT_SIZE == 0x1000
    assert first.args[0] == ("stk", ("rsp", 0), ((0, b"\x01"), (0xFF8, (7).to_bytes(4, "little"))))
    # an rsp slot says nothing about an rbp-based buffer
    assert second.args[0] == ("stk", ("rbp", -0x20))


def test_constant_bytes_come_only_from_file_backed_read_only_segments():
    m = model("dd_track_x86_64")
    assert m.const_bytes(_rodata(m, b"sixteen byte str"), 16) == b"sixteen byte str"
    assert m.const_bytes(_rodata(m, b"writable, not k!"), 16) is None          # .data: the program may change it
    ro = [(va, filesz) for va, _m, filesz, _o, fl in m.img.loads if not fl & 2 and not fl & 1][0]
    assert m.const_bytes(ro[0] + ro[1] - 8, 16) is None                         # runs past the file-backed end
    assert m.const_bytes(m.img.hi + 0x1000, 4) is None                          # outside every segment


# ================================================================== fix round 1: the stripped function-start scan
GAP_REAL = {"x86_64": ("gp_main", "gp_fwd", "gp_table", "gp_odd", "gp_tail", "gp_lone", "gp_lone2", "gp_after"),
            "arm64": ("gp_main", "gp_fwd", "gp_table", "gp_tail", "gp_lone", "gp_lone2", "gp_after")}


@pytest.mark.parametrize("arch", ARCHES)
def test_the_start_scan_finds_never_called_functions_and_splits_nothing_else(arch):
    full, bare = model("dd_gap_" + arch), model("dd_gap_%s_stripped" % arch)
    assert not bare.img.symtab
    real = {fn(full, n).addr: n for n in GAP_REAL[arch]}
    found = {a for a, f in bare.funcs.items() if f.stub is None}
    # exactly the real starts: code after a ret that a forward branch reaches (gp_fwd), that may be a
    # jump-table case (gp_table), or that is not 16-byte aligned (gp_odd, x86-64) is never split off; gp_lone
    # follows gp_tail's tail jump to gp_after, a function already known, which does not stop the split
    assert found == set(real)
    for name in ("gp_lone", "gp_lone2"):                 # nothing calls or references them
        assert bare.funcs[fn(full, name).addr].sources == {"gap"}
    assert bare.funcs[fn(full, "gp_fwd").addr].sources == {"call-target"}
    assert bare.funcs[fn(full, "gp_lone").addr].arity == 1 and not bare.notes
    # an image with its symbol table is not scanned: the symbols name its functions
    assert not any("gap" in f.sources for f in full.funcs.values())


def test_the_start_scan_can_be_turned_off_and_is_bounded(monkeypatch):
    full = model("dd_gap_x86_64")
    lone, lone2 = fn(full, "gp_lone").addr, fn(full, "gp_lone2").addr
    monkeypatch.setattr(dd, "MAX_GAP_ROUNDS", 1)          # gp_lone2 is only seen once gp_lone has a body
    once = dd.analyse(blob("dd_gap_x86_64_stripped"))
    assert lone in once.funcs and lone2 not in once.funcs
    assert "the function-start scan stopped after 1 rounds" in once.notes
    monkeypatch.setattr(dd, "SCAN_GAPS", False)
    off = dd.analyse(blob("dd_gap_x86_64_stripped"))
    assert lone not in off.funcs and lone2 not in off.funcs and not off.notes


@needs_unicorn
def test_solve_decodes_a_never_called_function_in_a_stripped_image(tmp_path):
    full = model("dd_lead_x86_64")
    orphan = fn(full, "dd_orphan").addr
    result = dd.solve(challenge(tmp_path, "dd_lead_x86_64_stripped"), CSCTF)
    # its one argument is open (an output buffer used as a number): it declines, but it is found and tried
    assert any("fcn.%08x@%#x(out) [no call site" % (orphan, orphan) in d
               for d in details(result, "decoder-candidate"))


# ================================================================== fix round 1: decoders that print
@needs_unicorn
@pytest.mark.parametrize("arch", ARCHES)
def test_solve_decodes_a_flag_a_decoder_only_prints(tmp_path, arch):
    result = dd.solve(challenge(tmp_path, "dd_print_" + arch), CSCTF)
    assert result.status == "candidate" and result.flags == (PRINT_FLAG.decode(),), result.notes
    lines = details(result, "emulate")
    m = model("dd_print_" + arch)
    assert any("dd_print_flag@%#x() [call site" % fn(m, "dd_print_flag").addr in d
               and "-> stdout %r via native_image" % ("flag: %s\n" % PRINT_FLAG.decode()) in d for d in lines)
    assert any("dd_putc_flag" in d and "-> stdout %r" % (PRINT_FLAG.decode() + "\n") in d for d in lines)
    assert any("dd_write_flag" in d and "-> stderr %r" % PRINT_FLAG.decode() in d for d in lines)
    # functions that only print what the image already holds are not evaluated (no decoder structure)
    assert not any(n in e.detail for e in result.evidence for n in ("dd_fmt", "dd_many", "dd_mixed", "dd_badfd"))
    # a decoder-like routine that calls an import nothing models is named, not run
    rand = [d for d in details(result, "decoder-candidate") if "dd_rand_decode@" in d]
    assert len(rand) == 1 and "calls unmodelled import(s) rand" in rand[0]
    assert rand[0].endswith("not evaluated: it calls an unmodelled import")


def test_rank_tells_a_printing_decoder_from_a_function_that_only_prints():
    m = model("dd_print_x86_64")
    by = {c.name: c for c in dd.rank(m)}
    assert "prints through printf (output captured)" in by["dd_print_flag"].reasons
    assert "prints through putchar (output captured)" in by["dd_putc_flag"].reasons
    plain = by["dd_fmt"]
    assert plain.reasons == ("1 bound call(s)", "only prints through printf (no loop, transform, byte or table "
                                                "access)")
    assert plain.score == 40 - 30
    assert "only prints through puts, write (no loop, transform, byte or table access)" in by["dd_mixed"].reasons
    # the output imports are captured, never "unmodelled"; rand is
    assert [c.name for c in by.values() if any("unmodelled" in r for r in c.reasons)] == ["dd_rand_decode"]
    rd = by["dd_rand_decode"]
    assert "calls unmodelled import(s) rand" in rd.reasons and not rd.func.scan.byte_mem and not rd.func.scan.table
    assert rd.score == 40 + 10 + min(20, 2 * rd.func.scan.transform) + 15 - 30      # bound, loop, name, import
    # any ONE kind of decoder structure makes a printing function a decoder candidate
    tk = {c.name: c for c in dd.rank(model("dd_track_x86_64"))}
    for name in ("tk_pr_loop", "tk_pr_byte", "tk_pr_table", "tk_unary_imp"):     # a loop; byte; indexed; xor
        assert "prints through puts (output captured)" in tk[name].reasons, (name, tk[name].reasons)
    assert any(r.startswith("only prints through puts") for r in tk["tk_pr_none"].reasons)


def test_an_output_with_line_breaks_and_tabs_shows_as_text():
    assert dd.Output("stdout", b"a\tb\r\n").show() == "stdout 'a\\tb\\r\\n'"
    assert dd.Output("stdout", b"a\x01").show() == "stdout hex 6101"


@needs_unicorn
def test_a_function_that_only_prints_is_named_when_a_lead_ranks_it(tmp_path):
    root = challenge(tmp_path, "dd_print_x86_64")
    _write_pseudo(root, "int main(void)\n{\n    sym.dd_fmt(0xffffffd6, 0x1cbe991a14);\n}\n")
    result = dd.solve(root, CSCTF)
    line = [d for d in details(result, "decoder-candidate") if "dd_fmt@" in d]
    assert line and "not evaluated: it only prints (no decoder structure)" in line[0]


@needs_unicorn
def test_evaluate_reports_what_a_call_printed():
    m = model("dd_print_x86_64")
    got, out = outputs(m, "dd_fmt", (("int", (-42) & M32), ("int", 123456789012)))
    want = "[%5d|%-4x|%04X|%c|%.3s|%d|%d|%06d|%%]\n" % (-42, 0xAB, 0xBEEF, "Z", "abcdef", 44, 123456789012, -42)
    assert got == {"stdout": want.encode()} and out.engine == "native_image"
    assert dd.Output("stdout", want.encode()).show() == "stdout %r" % want
    with pytest.raises(dd.Decline, match="through stdio and through write"):
        dd.evaluate(m, fn(m, "dd_mixed").addr, ())


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
