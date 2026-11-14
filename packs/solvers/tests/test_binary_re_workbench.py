"""B-165: the static-RE workbench toolkit (solvers/binary/re_workbench.py).

Every behaviour is proven with a known-answer check, not against the kit's own output: FNV/CRC use
published vectors, the time-lock is checked against the honest sequential squaring, and the capstone
/ lief wrappers run over bytes synthesised inside the test (a known opcode, a hand-built PE).
"""
from __future__ import annotations

import struct
import sys
import zlib

import pytest

import re_workbench as rw


# --------------------------------------------------------------------------- API-hash naming

def test_fnv1a32_matches_published_vectors():
    # FNV-1a 32-bit reference vectors (isthe.com/chongo/tech/comp/fnv).
    n = rw.ApiHashNamer("fnv1a32")
    assert n.hash("") == 0x811C9DC5
    assert n.hash("a") == 0xE40C292C
    assert n.hash("foobar") == 0xBF9CF968


def test_djb2_and_crc32_are_the_real_algorithms():
    assert rw.ApiHashNamer("djb2").hash("") == 5381
    assert rw.ApiHashNamer("crc32").hash("hello") == zlib.crc32(b"hello") & 0xFFFFFFFF
    # djb2a is the xor variant, distinct from djb2
    assert rw.ApiHashNamer("djb2a").hash("hello") != rw.ApiHashNamer("djb2").hash("hello")


def test_ror13_djb2_sdbm_known_answers():
    # ror13+add of "LoadLibraryA": the constant shellcode loaders push (0xEC0E4E8E)
    assert rw.ApiHashNamer("ror13").hash("LoadLibraryA") == 0xEC0E4E8E
    # djb2: h = h*33 + c from 5381; "a" -> 177670, "hello" -> 0x0F923099
    assert rw.ApiHashNamer("djb2").hash("a") == 177670
    assert rw.ApiHashNamer("djb2").hash("hello") == 0x0F923099
    # sdbm: h = c + h*65599 (65599 = 2^6 + 2^16 - 1); "a" -> 97, "ab" -> 97*65599 + 98
    assert rw.ApiHashNamer("sdbm").hash("a") == 97
    assert rw.ApiHashNamer("sdbm").hash("ab") == 97 * 65599 + 98 == 6363201


def test_hashes_agree_with_pe_emu_catalog():
    # one hash table in the repo: every scheme pe_emu also implements must agree on every name
    import pe_emu
    pairs = {"ror13": "ror13", "djb2": "djb2", "fnv1a32": "fnv1a", "crc32": "crc32"}
    for ours, theirs in pairs.items():
        for upper in (False, True):
            namer = rw.ApiHashNamer(ours, uppercase=upper)
            ref = pe_emu.HASHERS[theirs + ("_upper" if upper else "")]
            for name in rw.COMMON_WIN32_APIS:
                assert namer.hash(name) == ref(name), (ours, upper, name)
    # the default word list starts from pe_emu's catalog
    assert {n for _dll, n in pe_emu.COMMON_WINDOWS_APIS} <= set(rw.COMMON_WIN32_APIS)
    assert len(set(rw.COMMON_WIN32_APIS)) == len(rw.COMMON_WIN32_APIS)


def test_api_hash_namer_resolves_known_and_rejects_unknown():
    namer = rw.ApiHashNamer("ror13", names=rw.COMMON_WIN32_APIS)
    assert namer.resolve(0xEC0E4E8E) == "LoadLibraryA"   # the known constant, not namer's own output
    assert namer.resolve(0xDEADBEEF) is None          # not in the wordlist
    assert namer.candidates(0xDEADBEEF) == []
    upper = rw.ApiHashNamer("djb2", uppercase=True, names=rw.COMMON_WIN32_APIS)
    import pe_emu
    assert upper.resolve(pe_emu.hash_djb2("VirtualProtect", uppercase=True)) == "VirtualProtect"


def test_preprocessing_changes_the_hash():
    plain = rw.ApiHashNamer("ror13")
    upper = rw.ApiHashNamer("ror13", uppercase=True)
    term = rw.ApiHashNamer("ror13", include_terminator=True)
    assert plain.hash("GetProcAddress") != upper.hash("GetProcAddress")
    assert plain.hash("GetProcAddress") != term.hash("GetProcAddress")


def test_collision_is_reported_not_hidden():
    # a deliberately weak custom scheme: sum of bytes -> anagrams collide
    namer = rw.ApiHashNamer(scheme=lambda data, width, seed: sum(data), names=["ab", "ba", "zz"])
    assert namer.hash("ab") == namer.hash("ba")
    assert sorted(namer.candidates(ord("a") + ord("b"))) == ["ab", "ba"]
    with pytest.raises(rw.WorkbenchError, match="ambiguous"):
        namer.resolve(ord("a") + ord("b"))


def test_unknown_scheme_raises():
    with pytest.raises(rw.WorkbenchError, match="unknown hash scheme"):
        rw.ApiHashNamer("md5-ish")


# --------------------------------------------------------------------------- time-lock puzzle

def test_fastforward_equals_sequential_squaring():
    p, q = 10_007, 10_009
    n = p * q
    phi = (p - 1) * (q - 1)
    base = 1234
    for t in (0, 1, 7, 500):
        ff = rw.timelock_fastforward(base, t, n, phi)
        seq = rw.timelock_fastforward(base, t, n)
        assert ff.value == seq.value, t
        assert ff.method == "fast-forward" and ff.squarings == 0
        assert seq.method == "sequential" and seq.squarings == t


def test_sequential_value_is_the_defined_tower():
    # 3^(2^3) mod 100000 = 3^8 = 6561, by hand
    assert rw.timelock_fastforward(3, 3, 100_000).value == 6561


def test_fastforward_needs_coprime_base():
    p, q = 101, 103
    n, phi = p * q, (p - 1) * (q - 1)
    with pytest.raises(rw.WorkbenchError, match="gcd"):
        rw.timelock_fastforward(p, 50, n, phi)       # base shares factor p with n


def test_sequential_cap_is_enforced():
    with pytest.raises(rw.WorkbenchError, match="max_sequential"):
        rw.timelock_fastforward(2, 10, 97, max_sequential=5)


# ------------------------------------------------------------------------ env-fingerprint force

def test_force_environment_satisfies_mixed_constraints():
    cons = [
        rw.EnvConstraint("username", "eq", "SANDBOX-ADMIN"),
        rw.EnvConstraint("hostname", "suffix", "-ANALYSIS"),
        rw.EnvConstraint("hostname", "prefix", "DESKTOP-"),
        rw.EnvConstraint("domain", "oneof", ["CORP", "HOME"]),
        rw.EnvConstraint("domain", "ne", "HOME"),
    ]
    forced = rw.force_environment(cons)
    assert forced.satisfied, forced.conflicts
    assert forced.environment["username"] == "SANDBOX-ADMIN"
    assert forced.environment["hostname"].startswith("DESKTOP-")
    assert forced.environment["hostname"].endswith("-ANALYSIS")
    assert forced.environment["domain"] == "CORP"          # HOME excluded by ne
    # every constraint actually holds against the produced environment
    for c in cons:
        assert c.satisfied_by(forced.environment[c.key])


def test_contradictory_equality_is_reported():
    forced = rw.force_environment(
        [rw.EnvConstraint("cpuid_vendor", "eq", "GenuineIntel"),
         rw.EnvConstraint("cpuid_vendor", "eq", "AuthenticAMD")]
    )
    assert not forced.satisfied
    assert any("cpuid_vendor" in c for c in forced.conflicts)


def test_oneof_minus_ne_when_the_banned_value_sorts_first():
    # the verification probe: oneof{a,b} + ne 'a' must give 'b', not 'a_' and a false conflict
    forced = rw.force_environment([rw.EnvConstraint("user", "oneof", ["a", "b"]),
                                   rw.EnvConstraint("user", "ne", "a")])
    assert forced.satisfied and forced.conflicts == ()
    assert forced.environment == {"user": "b"}


def test_oneof_sets_intersect():
    forced = rw.force_environment([rw.EnvConstraint("d", "oneof", ["a", "b"]),
                                   rw.EnvConstraint("d", "oneof", ["b", "c"])])
    assert forced.satisfied and forced.environment == {"d": "b"}
    disjoint = rw.force_environment([rw.EnvConstraint("d", "oneof", ["a"]),
                                     rw.EnvConstraint("d", "oneof", ["b"])])
    assert not disjoint.satisfied
    assert disjoint.conflicts[0] == "d: oneof sets do not intersect"


def test_oneof_fully_excluded_by_ne_is_a_conflict():
    forced = rw.force_environment([rw.EnvConstraint("d", "oneof", ["a", "b"]),
                                   rw.EnvConstraint("d", "ne", "a"), rw.EnvConstraint("d", "ne", "b")])
    assert not forced.satisfied
    assert forced.conflicts[0] == "d: every allowed value ['a', 'b'] is excluded by ne"


def test_oneof_prefers_the_value_that_meets_the_affixes():
    forced = rw.force_environment([rw.EnvConstraint("h", "oneof", ["ALPHA", "DESKTOP-1"]),
                                   rw.EnvConstraint("h", "prefix", "DESKTOP-")])
    assert forced.satisfied and forced.environment == {"h": "DESKTOP-1"}


def test_ne_nudge_steers_an_affix_built_value_away():
    cons = [rw.EnvConstraint("user", "prefix", "user"), rw.EnvConstraint("user", "ne", "user")]
    forced = rw.force_environment(cons)
    assert forced.satisfied, forced.conflicts
    assert forced.environment["user"] == "user_"
    # with a suffix the nudge goes in the middle, so the suffix still holds
    forced = rw.force_environment([rw.EnvConstraint("h", "prefix", "PC-"), rw.EnvConstraint("h", "suffix", "-X"),
                                   rw.EnvConstraint("h", "ne", "PC--X")])
    assert forced.satisfied and forced.environment["h"] == "PC-_-X"


def test_every_contains_part_is_joined():
    # the verification probe: contains 'x' + contains 'y' must give a value holding both, not 'x'
    cons = [rw.EnvConstraint("h", "contains", "x"), rw.EnvConstraint("h", "contains", "y")]
    forced = rw.force_environment(cons)
    assert forced.satisfied and forced.conflicts == ()
    assert forced.environment == {"h": "xy"}
    # a part already inside another part (or an affix) is not repeated
    forced = rw.force_environment([rw.EnvConstraint("h", "prefix", "WIN-"),
                                   rw.EnvConstraint("h", "contains", "LAB"),
                                   rw.EnvConstraint("h", "contains", "AB"),
                                   rw.EnvConstraint("h", "contains", "WIN"),
                                   rw.EnvConstraint("h", "contains", "07")])
    assert forced.satisfied and forced.environment == {"h": "WIN-LAB07"}


def test_nested_prefixes_use_the_longest():
    forced = rw.force_environment([rw.EnvConstraint("h", "prefix", "ab"),
                                   rw.EnvConstraint("h", "prefix", "abc")])
    assert forced.satisfied and forced.conflicts == ()
    assert forced.environment == {"h": "abc"}
    # order does not matter
    forced = rw.force_environment([rw.EnvConstraint("h", "prefix", "abc"),
                                   rw.EnvConstraint("h", "prefix", "ab")])
    assert forced.satisfied and forced.environment == {"h": "abc"}


def test_nested_suffixes_use_the_longest():
    forced = rw.force_environment([rw.EnvConstraint("h", "suffix", "01"),
                                   rw.EnvConstraint("h", "suffix", "-01"),
                                   rw.EnvConstraint("h", "prefix", "PC")])
    assert forced.satisfied and forced.conflicts == ()
    assert forced.environment == {"h": "PC-01"}


def test_disagreeing_affixes_are_a_true_conflict():
    forced = rw.force_environment([rw.EnvConstraint("h", "prefix", "ab"),
                                   rw.EnvConstraint("h", "prefix", "ac")])
    assert not forced.satisfied
    assert forced.conflicts[0] == "h: prefixes ['ab', 'ac'] disagree (no value starts with all of them)"
    forced = rw.force_environment([rw.EnvConstraint("h", "suffix", "-01"),
                                   rw.EnvConstraint("h", "suffix", "02")])
    assert not forced.satisfied
    assert forced.conflicts[0] == "h: suffixes ['-01', '02'] disagree (no value ends with all of them)"


def test_final_check_catches_what_the_key_solver_cannot():
    # eq pins the value; the prefix check disagrees -> reported, never a plausible wrong environment
    forced = rw.force_environment([rw.EnvConstraint("user", "eq", "admin"),
                                   rw.EnvConstraint("user", "prefix", "sandbox-")])
    assert not forced.satisfied
    assert forced.environment == {"user": "admin"}
    assert forced.conflicts == ("user prefix 'sandbox-'",)
    banned = rw.force_environment([rw.EnvConstraint("user", "eq", "admin"),
                                   rw.EnvConstraint("user", "ne", "admin")])
    assert not banned.satisfied and banned.conflicts == ("user ne 'admin'",)


def test_bad_constraint_op_and_empty_oneof_raise():
    with pytest.raises(rw.WorkbenchError):
        rw.EnvConstraint("k", "startswith", "x")
    with pytest.raises(rw.WorkbenchError):
        rw.EnvConstraint("k", "oneof", [])


# --------------------------------------------------------------------------- accepted input

def test_per_position_solves_and_byte_proves():
    target = b"S3cr3t!"
    preds = [(lambda i: (lambda b: b == target[i]))(i) for i in range(len(target))]
    search = rw.AcceptedInputSearch(len(target), bytes(range(256)))
    res = search.solve_per_position(preds, check=lambda d: d == target)
    assert res.data == target
    assert res.verified is True
    assert res.underdetermined == ()


def test_per_position_reports_underdetermined_and_no_solution():
    search = rw.AcceptedInputSearch(2, b"AB")
    # position 0: only 'A'; position 1: both pass -> underdetermined
    res = search.solve_per_position([lambda b: b == ord("A"), lambda b: True])
    assert res.data[0] == ord("A")
    assert res.underdetermined == (1,)
    with pytest.raises(rw.WorkbenchError, match="no byte"):
        search.solve_per_position([lambda b: False, lambda b: True])


def test_hillclimb_recovers_input_from_separable_score():
    target = b"climb"
    search = rw.AcceptedInputSearch(len(target), bytes(range(0x20, 0x7F)))

    def score(d):
        return sum(1 for a, b in zip(d, target) if a == b)

    res = search.hillclimb(score, check=lambda d: d == target)
    assert res.data == target and res.verified


def test_verified_only_with_a_passing_check():
    target = b"ok"
    preds = [lambda b: b == ord("o"), lambda b: b == ord("k")]
    search = rw.AcceptedInputSearch(2, bytes(range(0x20, 0x7F)))
    # the search found the input, but nothing byte-proved it: verified stays False
    unproven = search.solve_per_position(preds)
    assert unproven.data == target and unproven.verified is False
    assert search.solve_per_position(preds, check=lambda d: False).verified is False

    def score(d):
        return sum(a == b for a, b in zip(d, target))

    climbed = search.hillclimb(score)
    assert climbed.data == target and climbed.verified is False
    assert search.hillclimb(score, check=lambda d: False).verified is False
    assert rw.AcceptedInputSearch.verify(target, lambda d: d == target) is True
    assert rw.AcceptedInputSearch.verify(b"no", lambda d: d == target) is False


# ----------------------------------------------------------------------- capstone / lief wrappers

@pytest.mark.needs_tool("py:capstone")
def test_disasm_decodes_known_x86_64_bytes():
    # xor rax, rax ; ret
    insns = rw.disasm(b"\x48\x31\xc0\xc3", "x86_64")
    assert [(i.mnemonic, i.op_str) for i in insns] == [("xor", "rax, rax"), ("ret", "")]
    assert insns[0].size == 3 and insns[1].address == 3


@pytest.mark.needs_tool("py:capstone")
def test_disasm_unknown_arch_raises():
    with pytest.raises(rw.WorkbenchError, match="unsupported arch"):
        rw.disasm(b"\x90", "sparc")


def _minimal_pe_with_export(dll_name="mydll.dll", export="MyExport") -> bytes:
    """A minimal real PE32+ carrying one named export, built from raw bytes inside the test."""
    FA = 0x200                      # file alignment == section alignment -> RVA == file offset
    sec_rva = FA
    expdir_rva = sec_rva
    eat_rva = expdir_rva + 40
    names_rva = eat_rva + 4
    nameord_rva = names_rva + 4
    dllname_rva = nameord_rva + 2
    dllname = dll_name.encode() + b"\x00"
    export_name = export.encode() + b"\x00"
    exportname_rva = dllname_rva + len(dllname)

    section = bytearray()

    def put(rva, data):
        off = rva - sec_rva
        if len(section) < off + len(data):
            section.extend(b"\x00" * (off + len(data) - len(section)))
        section[off:off + len(data)] = data

    put(expdir_rva, struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dllname_rva, 1, 1, 1,
                                eat_rva, names_rva, nameord_rva))
    put(eat_rva, struct.pack("<I", 0x3000))
    put(names_rva, struct.pack("<I", exportname_rva))
    put(nameord_rva, struct.pack("<H", 0))
    put(dllname_rva, dllname)
    put(exportname_rva, export_name)
    raw_size = (len(section) + FA - 1) // FA * FA
    section.extend(b"\x00" * (raw_size - len(section)))

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<IHHIIIHH", 0x00004550, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    opt = bytearray()
    opt += struct.pack("<HBB", 0x20B, 14, 0)
    opt += struct.pack("<III", 0, 0, 0)
    opt += struct.pack("<II", 0, 0x1000)
    opt += struct.pack("<Q", 0x180000000)
    opt += struct.pack("<II", FA, FA)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", sec_rva + raw_size)        # size of image
    opt += struct.pack("<I", FA)                         # size of headers
    opt += struct.pack("<I", 0)
    opt += struct.pack("<HH", 3, 0x400)
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<I", 16)
    datadirs = bytearray(16 * 8)
    struct.pack_into("<II", datadirs, 0, expdir_rva, 40)
    opt += datadirs
    sec = struct.pack("<8sIIIIIIHHI", b".edata\x00\x00", raw_size, sec_rva, raw_size, sec_rva,
                      0, 0, 0, 0, 0x40000040)
    out = bytearray()
    out += dos + coff + opt + sec
    out.extend(b"\x00" * (FA - len(out)))
    out += section
    return bytes(out)


@pytest.mark.needs_tool("py:lief")
def test_pe_export_names_reads_a_synthetic_export():
    data = _minimal_pe_with_export(export="SneakyExport")
    assert rw.pe_export_names(data) == ["SneakyExport"]


@pytest.mark.needs_tool("py:lief")
def test_pe_helpers_reject_non_pe_bytes():
    with pytest.raises(rw.WorkbenchError, match="not a PE"):
        rw.pe_export_names(b"this is not a PE image at all")
    with pytest.raises(rw.WorkbenchError, match="not a PE"):
        rw.pe_import_names(b"\x00" * 64)


@pytest.mark.needs_tool("py:lief")
def test_pe_import_names_empty_on_export_only_pe():
    # the synthetic PE has an export table but no import table: the loop yields nothing, no crash
    assert rw.pe_import_names(_minimal_pe_with_export()) == []


def _minimal_pe_with_imports() -> bytes:
    """A PE32+ with .text and one .idata section importing KERNEL32.dll!VirtualAlloc and
    KERNEL32.dll!GetProcAddress, built from raw bytes inside the test."""
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)                  # entry point
    struct.pack_into("<I", data, opt + 20, 0x1000)                  # base of code
    struct.pack_into("<Q", data, opt + 24, 0x140000000)             # image base
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)          # section / file alignment
    struct.pack_into("<HHHHHH", data, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", data, opt + 52, 0, 0x3000, 0x200)      # size of image / headers
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<QQQQ", data, opt + 72, 1 << 20, 0x1000, 1 << 20, 0x1000)
    struct.pack_into("<II", data, opt + 104, 0, 16)
    struct.pack_into("<II", data, opt + 112 + 8, 0x2000, 40)        # import directory
    table = opt + 0xF0
    for i, (name, rva, raw_at, flags) in enumerate(((b".text\0\0\0", 0x1000, 0x200, 0x60000020),
                                                     (b".idata\0\0", 0x2000, 0x400, 0xC0000040))):
        at = table + i * 40
        data[at:at + 8] = name
        struct.pack_into("<IIIIIIHHI", data, at + 8, 0x200, rva, 0x200, raw_at, 0, 0, 0, 0, flags)
    data[0x200] = 0xC3                                              # ret
    idata = 0x400                                                   # file offset of RVA 0x2000
    # descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk; then a null one
    struct.pack_into("<IIIII", data, idata, 0x2040, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<QQQ", data, idata + 0x40, 0x2090, 0x20A0, 0)  # import lookup table
    struct.pack_into("<QQQ", data, idata + 0x60, 0x2090, 0x20A0, 0)  # import address table
    data[idata + 0x80:idata + 0x80 + 13] = b"KERNEL32.dll\0"
    data[idata + 0x90:idata + 0x90 + 15] = b"\0\0VirtualAlloc\0"
    data[idata + 0xA0:idata + 0xA0 + 17] = b"\0\0GetProcAddress\0"
    return bytes(data)


@pytest.mark.needs_tool("py:lief")
def test_pe_import_names_reads_a_synthetic_import_table():
    data = _minimal_pe_with_imports()
    assert rw.pe_import_names(data) == ["KERNEL32.dll!VirtualAlloc", "KERNEL32.dll!GetProcAddress"]
    # an independent reader (pe_emu's bounded mapper) sees the same imports in the same bytes
    import pe_emu
    mapped = pe_emu.map_pe(data)
    assert [(s.dll, s.name) for s in mapped.imports] == [("kernel32.dll", "VirtualAlloc"),
                                                         ("kernel32.dll", "GetProcAddress")]  # pe_emu lowercases


def test_pe_readers_cap_the_input_size(monkeypatch):
    assert rw.MAX_PE_BYTES == __import__("pe_emu").MAX_FILE
    monkeypatch.setattr(rw, "MAX_PE_BYTES", 64)
    with pytest.raises(rw.WorkbenchError, match="cap"):
        rw.pe_import_names(b"MZ" + b"\0" * 100)
    with pytest.raises(rw.WorkbenchError, match="cap"):
        rw.pe_export_names(b"MZ" + b"\0" * 100)


@pytest.mark.parametrize("tool,call", [
    ("capstone", lambda: rw.disasm(b"\x90")),
    ("lief", lambda: rw.pe_export_names(b"MZ")),
    ("lief", lambda: rw.pe_import_names(b"MZ")),
])
def test_missing_library_raises_tool_unavailable(monkeypatch, tool, call):
    monkeypatch.setitem(sys.modules, tool, None)            # `import <tool>` now raises ImportError
    with pytest.raises(rw.ToolUnavailable) as err:
        call()
    assert err.value.tool == tool
    assert str(err.value).startswith(f"{tool}: import ") and "install it into the venv" in str(err.value)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
