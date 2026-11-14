"""The reusable parsers carried from Huntress speedrun/solvers (B-001 hand-merge batch hm-12).

binary_facts (ELF/PE/jar/HCFG facts), metadata_zip (lean zip reader), metadata_d30 (identical-hash groups,
execution chain) and mobile_jit (pure Dalvik method compiler). Every fixture is built here from scratch.
"""
import importlib.util
import io
import json
import struct
import zipfile
import zlib
from pathlib import Path

from speedrun.solvers import binary_facts, metadata_d30, metadata_zip, mobile_jit

ROOT = Path(__file__).resolve().parent.parent


def _zip(members, method=zipfile.ZIP_DEFLATED, comment=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=method) as z:
        for name, data in members:
            z.writestr(name, data)
        z.comment = comment
    return buf.getvalue()


def _elf64(e_type=2, e_machine=62, entry=0x401040):
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    rest = struct.pack("<HHIQQQIHHHHHH", e_type, e_machine, 1, entry, 64, 0, 0, 64, 56, 0, 64, 0, 0)
    return (ident + rest).ljust(128, b"\0")


def _hcfg(obj, key=0x5A, version=1):
    plain = json.dumps(obj).encode()
    enc = bytes(b ^ key for b in plain)
    return b"HCFG" + bytes([version, key]) + struct.pack("<HI", len(enc), zlib.crc32(plain)) + enc


# -- binary_facts ---------------------------------------------------------------------------------------------

def test_binary_facts_elf64_header_numbers():
    f = binary_facts.facts("x.elf", _elf64(e_type=3, entry=0x1234))
    assert f["format"] == "elf"
    assert (f["elf_class"], f["machine"], f["elf_type"], f["endianness"]) == ("ELF64", "x86-64", "ET_DYN", "little")
    assert (f["elf_bits"], f["machine_id"], f["elf_type_id"], f["ei_data"], f["entry"]) == (64, 62, 3, 1, 0x1234)


def test_binary_facts_pe_machine_is_coff_machine():
    pe = bytearray(0x200)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x84, 0x14C)
    struct.pack_into("<H", pe, 0x80 + 24, 0x10B)
    f = binary_facts.facts("x.exe", bytes(pe))
    assert f["format"].startswith("pe")
    assert f["machine"] == "i386"
    assert f["machine_id"] == 0x14C
    assert f.get("elf_class") is None


def test_binary_facts_hcfg_valid_container_wins_over_decoy():
    good = _hcfg({"flag_hint": "ok"}, key=0x21)
    decoy = bytearray(_hcfg({"flag_hint": "decoy"}, key=0x33))
    decoy[8] ^= 0xFF                                  # break the CRC: the decoy must be skipped
    f = binary_facts.facts("blob.bin", b"junk" + bytes(decoy) + b"\0" * 7 + good)
    assert f["hcfg"] == {"version": 1, "key": 0x21, "crc": zlib.crc32(json.dumps({"flag_hint": "ok"}).encode()),
                         "json": {"flag_hint": "ok"}}
    assert binary_facts.facts("blob.bin", bytes(decoy))["hcfg"] is None


def test_binary_facts_jar_methods_and_base64_hcfg_in_class():
    import base64
    cls = b"\xca\xfe\xba\xbe" + b"\0" * 20 + base64.b64encode(_hcfg({"k": 7})) + b"\0"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("META-INF/"), b"")
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", compress_type=zipfile.ZIP_STORED)
        z.writestr("a/Main.class", cls, compress_type=zipfile.ZIP_DEFLATED)
    f = binary_facts.facts("x.jar", buf.getvalue())
    assert f["format"] == "jar"
    assert f["compression_methods"] == [0, 8]
    assert f["hcfg"]["json"] == {"k": 7}


# -- metadata_zip ---------------------------------------------------------------------------------------------

def test_metadata_zip_lite_matches_zipfile():
    members = [("a.txt", b"alpha" * 50), ("dir/b.bin", bytes(range(256))), ("c", b"")]
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        d = _zip(members, method=method)
        z = metadata_zip.open_zip(d)
        assert isinstance(z, metadata_zip.Lite)
        ref = zipfile.ZipFile(io.BytesIO(d))
        assert z.namelist() == ref.namelist()
        for n in ref.namelist():
            assert z.read(n) == ref.read(n)
            assert z.getinfo(n).file_size == ref.getinfo(n).file_size


def test_metadata_zip_unusual_shape_falls_back_to_zipfile():
    d = _zip([("a.txt", b"hello")], comment=b"trailing comment")
    z = metadata_zip.open_zip(d)
    assert isinstance(z, zipfile.ZipFile)
    assert z.read("a.txt") == b"hello"


def test_metadata_zip_non_zip_raises():
    try:
        metadata_zip.open_zip(b"not a zip at all, definitely" * 3)
    except zipfile.BadZipFile:
        return
    raise AssertionError("a non-zip must raise BadZipFile, not return a view")


def test_metadata_zip_missing_member_raises_keyerror():
    z = metadata_zip.open_zip(_zip([("a.txt", b"x")]))
    try:
        z.read("nope")
    except KeyError:
        return
    raise AssertionError("reading a missing member must raise KeyError")


# -- metadata_d30 ---------------------------------------------------------------------------------------------

def test_identical_sha256_groups():
    d = _zip([("art/one.bin", b"same"), ("art/two.dat", b"same"), ("art/three.txt", b"other"),
              ("x/four.log", b"pair"), ("five.log", b"pair")])
    assert metadata_d30.identical_sha256_groups("z.zip", d) == '[["five","four"],["one","two"]]'
    assert metadata_d30.identical_sha256_groups("z.zip", _zip([("a.b", b"1"), ("c.d", b"2")])) is None
    assert metadata_d30.identical_sha256_groups("z.zip", b"MZ not a zip") is None


def test_execution_chain_single_walk():
    d = _zip([("dropper.ps1", b"Start-Process loader.exe"),
              ("loader.exe", b"MZ...loads payload_dll from disk"),
              ("payload_dll.dll", b"final stage, references nothing")])
    assert metadata_d30.execution_chain("z.zip", d) == '["dropper","loader","payload_dll"]'


def test_execution_chain_branch_is_not_guessed():
    d = _zip([("start.bat", b"run alpha and beta"), ("alpha.exe", b"x"), ("beta.exe", b"y")])
    assert metadata_d30.execution_chain("z.zip", d) is None


# -- mobile_jit -----------------------------------------------------------------------------------------------

# sum(range(n)) as an int, wrapping at 32 bits:
#   const/4 v0,0; const/4 v1,0; L: if-ge v1,v2,+6; add-int/2addr v0,v1; add-int/lit8 v1,v1,1; goto L; return v0
_SUM_LOOP = [0x0012, 0x0112, 0x2135, 0x0006, 0x10B0, 0x01D8, 0x0101, 0xFB28, 0x000F]


def _private_codec():
    spec = importlib.util.spec_from_file_location("dex_chain_codec_hm12",
                                                  ROOT / "solvers/mobile-android/dex_chain_codec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Dex:
    def __init__(self, code):
        self.code = code


def _s32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x & 0x80000000 else x


def test_mobile_jit_matches_interpreter_value_and_steps():
    plain, jitted = _private_codec(), _private_codec()
    mobile_jit.install(jitted)
    assert getattr(jitted.VM, "_speed_jit", False) and not getattr(plain.VM, "_speed_jit", False)
    dex = _Dex({0: (3, 1, _SUM_LOOP)})
    for n in (0, 1, 10, 100_000):             # 100000 overflows int32: the wrap must match
        a, b = plain.VM(dex), jitted.VM(dex)
        va, vb = a.run(0, [n]), b.run(0, [n])
        assert va == vb == _s32(sum(range(n)))
        assert a.steps == b.steps


def test_mobile_jit_compiles_only_pure_methods():
    W = _private_codec()._W
    f = mobile_jit.compile_method(3, 1, _SUM_LOOP, W, {})
    assert f is not None and f([5], 10_000)[0] == 10
    invoke = [0x1071, 0x0000, 0x0000, 0x000E]   # invoke-static {}, method@0; return-void
    assert mobile_jit.compile_method(1, 0, invoke, W, {}) is None


def test_mobile_jit_budget_falls_back_to_interpreter_decline():
    plain, jitted = _private_codec(), _private_codec()
    mobile_jit.install(jitted)
    dex = _Dex({0: (3, 1, _SUM_LOOP)})
    outcomes = []
    for mod in (plain, jitted):
        vm = mod.VM(dex)
        vm.max_steps = 50
        try:
            vm.run(0, [1000])
            outcomes.append("ran")
        except Exception as e:  # noqa: BLE001 - the interpreter's own decline type
            outcomes.append(type(e).__name__)
    assert outcomes[0] == outcomes[1] != "ran"
