"""B-011: decompile-on-intake for every ELF/PE/Mach-O/.NET binary.

Most tests run with no external tool: format classification, ELF ``.init_array`` parsing (synthetic
ELF bytes), the r2 sentinel split (canned r2 output), backend selection and the loud missing-tool
failure, and the ``solve`` adapter driven by a stub backend. Two tests exercise the real r2ghidra
decompiler on a binary compiled from source in the test; they are marked ``needs_tool`` so they are
reported NOT RUN when radare2 / cc are absent, never silently green.
"""
from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "binary"))

import decompile_intake as di          # noqa: E402  (flat import, the engine sys.path)
from ctf import event                  # noqa: E402
from ctf.engines import manifest as _manifest, runner as _runner   # noqa: E402
from ctf.intake import engines as _intake_engines                  # noqa: E402
from ctf.result import SolverResult    # noqa: E402

CSCTF = event.load("csctf")


# ---------------------------------------------------------------- classification
def test_classify_recognises_each_executable_format():
    assert di.classify(b"\x7fELF\x02\x01\x01\x00") == "elf"
    assert di.classify(b"MZ\x90\x00\x03") == "pe"
    assert di.classify(b"\xcf\xfa\xed\xfe\x0c") == "macho"       # Mach-O 64 LE
    assert di.classify(b"\xca\xfe\xba\xbe") == "macho"           # fat Mach-O
    assert di.classify(b"%PDF-1.7") is None
    assert di.classify(b"PK\x03\x04") is None
    assert di.classify(b"") is None


def test_is_dotnet_needs_both_pe_header_and_metadata_signature():
    assert di.is_dotnet(b"MZ" + b"\x00" * 200 + b"BSJB" + b"\x00" * 8)
    assert not di.is_dotnet(b"MZ" + b"\x00" * 200)              # native PE: no metadata root
    assert not di.is_dotnet(b"\x7fELF" + b"BSJB")               # not a PE at all


# ---------------------------------------------------------------- ELF constructors
def _elf_with_init_array(ptrs, *, bits=64, little=True):
    """A minimal ELF carrying one SHT_INIT_ARRAY section with the given pointer values."""
    en = "<" if little else ">"
    ei_class = 2 if bits == 64 else 1
    ei_data = 1 if little else 2
    ptr_code = "Q" if bits == 64 else "I"
    ptr_sz = 8 if bits == 64 else 4
    ehdr_sz = 64 if bits == 64 else 52
    shent = 64 if bits == 64 else 40
    init_off = ehdr_sz
    init_data = b"".join(struct.pack(en + ptr_code, p) for p in ptrs)
    shoff = init_off + len(init_data)
    # ELF identification + header
    e = bytearray(b"\x7fELF")
    e += bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    e += struct.pack(en + "HH", 2, 0x3E if bits == 64 else 3)   # e_type, e_machine
    e += struct.pack(en + "I", 1)                               # e_version
    if bits == 64:
        e += struct.pack(en + "Q", 0)                           # e_entry
        e += struct.pack(en + "Q", 0)                           # e_phoff
        e += struct.pack(en + "Q", shoff)                       # e_shoff (0x28)
    else:
        e += struct.pack(en + "I", 0) + struct.pack(en + "I", 0) + struct.pack(en + "I", shoff)
    e += struct.pack(en + "I", 0)                               # e_flags
    e += struct.pack(en + "H", ehdr_sz)                         # e_ehsize
    e += struct.pack(en + "HH", 0, 0)                           # e_phentsize, e_phnum
    e += struct.pack(en + "HH", shent, 1)                       # e_shentsize, e_shnum (one section)
    e += struct.pack(en + "H", 0)                               # e_shstrndx
    assert len(e) == ehdr_sz, len(e)
    buf = bytearray(e)
    buf += init_data
    assert len(buf) == shoff
    # one section header: SHT_INIT_ARRAY
    sh = bytearray()
    sh += struct.pack(en + "I", 0)                              # sh_name
    sh += struct.pack(en + "I", di._SHT_INIT_ARRAY)            # sh_type
    if bits == 64:
        sh += struct.pack(en + "Q", 0)                         # sh_flags
        sh += struct.pack(en + "Q", 0)                         # sh_addr
        sh += struct.pack(en + "Q", init_off)                 # sh_offset
        sh += struct.pack(en + "Q", len(init_data))           # sh_size
        sh += b"\x00" * (shent - len(sh))
    else:
        sh += struct.pack(en + "I", 0)                         # sh_flags
        sh += struct.pack(en + "I", 0)                         # sh_addr
        sh += struct.pack(en + "I", init_off)                 # sh_offset
        sh += struct.pack(en + "I", len(init_data))           # sh_size
        sh += b"\x00" * (shent - len(sh))
    buf += sh
    return bytes(buf)


def test_init_array_targets_reads_constructor_pointers_64_le():
    data = _elf_with_init_array([0x1149, 0, 0x1200])           # a null sentinel is dropped
    assert di.init_array_targets(data) == [0x1149, 0x1200]


def test_init_array_targets_reads_32_bit_big_endian():
    data = _elf_with_init_array([0x8048400, 0xFFFFFFFF, 0x8048500], bits=32, little=False)
    assert di.init_array_targets(data) == [0x8048400, 0x8048500]   # ~0 sentinel dropped


def test_init_array_targets_empty_for_non_elf_or_no_section():
    assert di.init_array_targets(b"MZ" + b"\x00" * 100) == []
    assert di.init_array_targets(b"\x7fELF") == []                  # truncated header


# ---------------------------------------------------------------- r2 output parsing
def test_split_sentinels_separates_functions_and_drops_empties():
    blob = (
        "===CTF-DECOMP-FN:main===\n"
        "uint main(void)\n{\n    return 0;\n}\n"
        "===CTF-DECOMP-FN:ctor_0x1149===\n"
        "void ctor(void)\n{\n}\n"
        "===CTF-DECOMP-FN:entry0===\n"
        "   \n"                                                     # empty body: dropped
    )
    out = di._split_sentinels(blob)
    assert [name for name, _ in out] == ["main", "ctor_0x1149"]
    assert "uint main" in out[0][1]


# ---------------------------------------------------------------- backend selection
def test_select_backend_fails_loudly_when_no_tool_is_installed(monkeypatch):
    monkeypatch.setattr(di, "_resolve", lambda *names: None)
    di._r2_pdg_cache.clear()
    with pytest.raises(di.NoDecompiler) as ei:
        di.select_backend("elf")
    assert "radare2" in str(ei.value) and "ghidra" in str(ei.value).lower()
    with pytest.raises(di.NoDecompiler) as ed:
        di.select_backend("dotnet")
    assert "ilspycmd" in str(ed.value)


def test_select_backend_picks_r2ghidra_when_available(monkeypatch):
    monkeypatch.setattr(di.R2GhidraBackend, "available", lambda self: True)
    monkeypatch.setattr(di.GhidraHeadlessBackend, "available", lambda self: False)
    b = di.select_backend("elf")
    assert b.name == "r2ghidra"


# ---------------------------------------------------------------- stub-backend solve()
class _FakeBackend:
    name = "fake"
    formats = ("elf", "pe", "macho")

    def __init__(self, blocks):
        self._blocks = blocks

    def available(self):
        return True

    def decompile(self, binary, fmt, data, timeout):
        return list(self._blocks)


def _challenge_with(tmp_path, name="prog", head=b"\x7fELF\x02\x01\x01\x00", extra=b"\x00" * 64):
    files = tmp_path / "files"
    files.mkdir()
    (files / name).write_bytes(head + extra)
    return tmp_path


def test_solve_none_when_there_is_no_binary(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "readme.txt").write_text("hello")
    res = di.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert "no ELF" in res.notes or "no" in res.notes.lower()


def test_solve_writes_pseudocode_and_reports_none_without_a_flag(tmp_path, monkeypatch):
    ch = _challenge_with(tmp_path)
    monkeypatch.setattr(di, "select_backend",
                        lambda fmt: _FakeBackend([("main", "int main(void){return 0;}")]))
    res = di.solve(ch, CSCTF)
    assert res.status == "none"
    written = ch / "recon" / "decompile" / "files__prog" / "main.c"
    assert written.is_file()
    assert "int main" in written.read_text()
    assert any(e.kind == "decompile" and e.path.endswith("main.c") for e in res.evidence)


def test_solve_returns_candidate_when_a_flag_is_in_the_pseudocode(tmp_path, monkeypatch):
    ch = _challenge_with(tmp_path)
    code = 'int check(char*s){return strcmp(s,"CSCTF{decompiled_at_intake}");}'
    monkeypatch.setattr(di, "select_backend", lambda fmt: _FakeBackend([("check", code)]))
    res = di.solve(ch, CSCTF)
    assert res.status == "candidate"
    assert "CSCTF{decompiled_at_intake}" in res.flags
    assert res.evidence                     # the decompiled file is cited


def test_solve_blocked_when_no_decompiler_fits_any_binary(tmp_path, monkeypatch):
    ch = _challenge_with(tmp_path)

    def _raise(fmt):
        raise di.NoDecompiler("no decompiler for elf: install radare2 with the r2ghidra pdg plugin")
    monkeypatch.setattr(di, "select_backend", _raise)
    res = di.solve(ch, CSCTF)
    assert res.status == "blocked"
    assert "radare2" in res.notes and "r2ghidra" in res.notes
    assert res.flags == ()                   # blocked never carries a flag


def test_solve_unsure_when_some_decompile_and_some_fail(tmp_path, monkeypatch):
    files = tmp_path / "files"
    files.mkdir()
    (files / "good").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    (files / "bad").write_bytes(b"MZ\x90\x00" + b"\x00" * 64)

    def _pick(fmt):
        if fmt == "elf":
            return _FakeBackend([("main", "int main(void){}")])
        raise di.NoDecompiler("no decompiler for pe")
    monkeypatch.setattr(di, "select_backend", _pick)
    res = di.solve(ch := tmp_path, CSCTF)
    assert res.status == "unsure"
    assert (ch / "recon" / "decompile" / "files__good" / "main.c").is_file()
    assert "could not decompile" in res.notes


def test_decompile_file_skips_an_oversized_file(tmp_path, monkeypatch):
    f = tmp_path / "huge"
    f.write_bytes(b"\x7fELF" + b"\x00" * 10)
    monkeypatch.setattr(di, "MAX_FILE_BYTES", 8)
    out = di.decompile_file(f, tmp_path / "o")
    assert out.backend is None and "over the" in out.note


# ---------------------------------------------------------------- manifest / intake wiring
def test_manifest_is_valid_and_wired_for_intake():
    m = _manifest.load(Path(__file__).resolve().parents[1]
                       / "solvers" / "binary" / "decompile_intake.manifest.toml")
    assert m.id == "binary.decompile_intake"
    assert m.entry.kind == "function" and m.entry.function == "solve"
    assert m.cost_class == "heavy" and m.status == "active"
    assert m.intake is not None
    assert m.intake.select == "files" and m.intake.run == "challenge" and m.intake.spawns is True
    assert "magic:0x7f454c46" in m.intake.match      # ELF
    assert {r.category[0] for r in m.routes if r.category} >= {"reverse", "pwn"}


def _guard(allows_spawn, reason="hook guard"):
    import types
    return types.SimpleNamespace(allows_spawn=allows_spawn, reason=reason)


def test_intake_plan_runs_it_under_the_os_sandbox_at_heavy_cap(tmp_path):
    (tmp_path / "bin").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    mans = [m for m in _manifest.discover() if m.id == "binary.decompile_intake"]
    assert mans, "engine not discovered"
    plan = _intake_engines.plan(mans, "reverse", "a stripped elf crackme", tmp_path,
                                guard=_guard(True), max_cost="heavy")
    assert [j.engine for j in plan.jobs] == ["binary.decompile_intake"]
    assert plan.jobs[0].files == ()          # run = challenge: the whole folder


def test_intake_skips_it_without_the_os_sandbox_because_it_spawns(tmp_path):
    (tmp_path / "bin").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    mans = [m for m in _manifest.discover() if m.id == "binary.decompile_intake"]
    plan = _intake_engines.plan(mans, "reverse", "", tmp_path, guard=_guard(False), max_cost="heavy")
    assert not plan.jobs
    assert any(s.engine == "binary.decompile_intake" and "starts other programs" in s.reason
               for s in plan.skipped)


def test_intake_skips_it_at_the_default_cheap_cap(tmp_path):
    (tmp_path / "bin").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    mans = [m for m in _manifest.discover() if m.id == "binary.decompile_intake"]
    plan = _intake_engines.plan(mans, "reverse", "", tmp_path, guard=_guard(True), max_cost="cheap")
    assert not plan.jobs
    assert any(s.engine == "binary.decompile_intake" and "cost_class heavy" in s.reason
               for s in plan.skipped)


# ---------------------------------------------------------------- real r2ghidra (NOT RUN without tools)
_C_SRC = r'''
#include <string.h>
#include <stdio.h>
int check(const char *s){ return strcmp(s, "CSCTF{real_decompile}"); }
int main(int argc, char **argv){ if(argc>1 && !check(argv[1])) puts("ok"); return 0; }
'''


@pytest.mark.needs_tool("radare2", "cc")
def test_r2ghidra_decompiles_main_of_a_self_compiled_binary(tmp_path):
    src = tmp_path / "c.c"
    src.write_text(_C_SRC)
    binp = tmp_path / "c.bin"
    subprocess.run(["cc", "-O0", "-o", str(binp), str(src)], check=True)
    di._r2_pdg_cache.clear()
    backend = di.R2GhidraBackend()
    assert backend.available(), "radare2 lacks the r2ghidra pdg plugin"
    out = di.decompile_file(binp, tmp_path / "out")
    assert out.backend == "r2ghidra"
    assert "main" in out.functions, out.note
    assert "main.c" in out.functions["main"]
    assert "return" in (tmp_path / "out" / "main.c").read_text().lower()


@pytest.mark.needs_tool("radare2", "cc")
def test_solve_end_to_end_decompiles_a_real_binary_into_the_workspace(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    src = tmp_path / "c.c"
    src.write_text(_C_SRC)
    subprocess.run(["cc", "-O0", "-o", str(files / "crackme"), str(src)], check=True)
    di._r2_pdg_cache.clear()
    res = di.solve(tmp_path, CSCTF)
    assert res.status in ("none", "candidate"), res.notes
    out = tmp_path / "recon" / "decompile" / "files__crackme" / "main.c"
    assert out.is_file() and out.read_text().strip()
    assert isinstance(res, SolverResult)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
