"""B-167: Python / JVM bytecode recovery + a packer-unpack set, run in the sandbox at intake.

Every test fakes ``tools/sandbox.py`` by injecting a stand-in module into
``sandbox_recover._SANDBOX`` (the same seam the engine uses to load the real client by path), so no
Docker, no sandbox image and no real decompiler is needed: the tests exercise the format sniffing,
the per-tool dispatch (primary then fallback), the parsing of a tool's stdout / output files, and the
loud ``blocked`` when the sandbox is down. Fixtures (a pyc head, a Java class head, a jar, a packed
ELF, a PyInstaller archive) are built by hand from their magic bytes; no real challenge file is
committed, and no challenge bytecode is ever executed. Time is driven by an injected step clock, never
by the wall clock.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import importlib.util
import io
import lzma
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "binary"))

import sandbox_recover as sr          # noqa: E402  (flat import, the engine sys.path)
from ctf import event                 # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CSCTF = event.load("csctf")
FLAG = "csctf{p1e_r3c0v3ry_in_7h3_s4ndb0x}"
DENIED = ("the Docker daemon does not answer (permission denied while trying to connect to the docker "
          "API at unix:///run/user/docker.sock)")


# ------------------------------------------------------------------ the fake sandbox
class FakeResult:
    def __init__(self, code=0, stdout=b"", stderr=b"", files=None, note="", seconds=0.01):
        self.code, self.stdout, self.stderr = code, stdout, stderr
        self.files, self.out_dir, self.note, self.seconds = files or {}, None, note, seconds
        self.image = "csctf-sandbox:2"

    @property
    def timed_out(self):
        return self.code == 124


class FakeSandbox:
    """A stand-in for tools/sandbox.py: ``run`` replays a per-tool scripted response, ``upx_unpack``
    a scripted (bytes, note) pair. A tool with no scripted response raises SandboxDown (the sandbox
    cannot run it), which is what a missing-from-image / not-started tool does."""

    def __init__(self):
        self.responses = {}          # tool -> FakeResult | Exception | callable(tool, args, inputs)
        self.upx = (None, "no UPX! signature in an ELF, PE or Mach-O image")
        self.calls = []              # (tool, args, input_names, timeout)
        self.starts = []             # the start= of each run / upx_unpack call
        self.bodies = []             # (tool, first input's bytes)
        self.upx_calls = []          # (data, timeout)
        self.on_run = None           # called with the timeout of each call (a step clock hooks in here)

    class SandboxDown(Exception):
        pass

    class Lit(str):
        pass

    def run(self, tool, args=(), inputs=(), timeout=60.0, keep=False, executable=False, start=True):
        self.calls.append((tool, list(args), [i[0] for i in inputs], timeout))
        self.starts.append(start)
        self.bodies.append((tool, inputs[0][1] if inputs else b""))
        if self.on_run:
            self.on_run(timeout)
        resp = self.responses.get(tool)
        if resp is None:
            raise self.SandboxDown(f"{tool} is not in csctf-sandbox:2")
        if isinstance(resp, Exception):
            raise resp
        if callable(resp):
            return resp(tool, list(args), list(inputs))
        return resp

    def upx_unpack(self, data, timeout, start=True):
        self.upx_calls.append((data, timeout))
        self.starts.append(start)
        if self.on_run:
            self.on_run(timeout)
        return self.upx


@pytest.fixture
def fake(monkeypatch):
    fk = FakeSandbox()
    monkeypatch.setattr(sr, "_SANDBOX", fk)
    return fk


class FakeDecompile:
    """A stand-in for decompile_intake.decompile_file (the native decompiler is a collaborator)."""

    def __init__(self, functions=None, pseudocode="", note="", backend="r2ghidra"):
        self.result = type("Out", (), {"functions": functions or {}, "pseudocode": pseudocode, "note": note,
                                       "backend": backend, "ok": bool(functions)})()
        self.calls = []

    def __call__(self, path, outdir, *, timeout, challenge_dir):
        self.calls.append((Path(path), Path(outdir), timeout, Path(challenge_dir)))
        return self.result


@pytest.fixture
def decomp(monkeypatch):
    d = FakeDecompile(functions={"main": "recon/decompile/x/main.c"}, pseudocode="int main(void) { return 0; }")
    monkeypatch.setattr(sr, "_DECOMPILE", d)
    return d


class StepClock:
    """A clock that only moves when told to: time is what the fake tools say they took."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


# ------------------------------------------------------------------ fixture builders
PYC_312 = bytes.fromhex("cb0d0d0a")


def pyc_bytes(body=b"\x00" * 20) -> bytes:
    """A .pyc head: the CPython 3.12 magic (cb 0d 0d 0a), a bit field, mtime, source size, then body."""
    return PYC_312 + b"\x00" * 12 + body


def class_bytes(major=52, tail=b"\x00" * 8) -> bytes:
    """A Java .class head: CA FE BA BE, minor=0, the given major_version, then a tiny tail."""
    return b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + major.to_bytes(2, "big") + tail


def fat_macho_bytes(nfat=2) -> bytes:
    """A Mach-O fat header: FAT_MAGIC (CA FE BA BE) then a u32 nfat_arch -- NOT a Java class."""
    return b"\xca\xfe\xba\xbe" + nfat.to_bytes(4, "big") + b"\x00" * 20


def zip_bytes(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def jar_bytes(extra=b"") -> bytes:
    return zip_bytes({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "Main.class": class_bytes() + extra})


def plain_zip_bytes() -> bytes:
    return zip_bytes({"notes.txt": b"nothing to see"})


def upx_elf_bytes(extra=b"") -> bytes:
    return b"\x7fELF" + b"\x00" * 40 + b"UPX!" + b"\x00" * 40 + extra


PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
CODE = b"\xe3" + b"\x01" * 30          # stands for a marshalled code object; never unmarshalled


def pyi_bytes(entries, pyver=312) -> bytes:
    """A synthetic PyInstaller executable: an ELF head, the members, the TOC, and a v2.1 cookie.
    entries: (name, typecode, data) triples, stored uncompressed."""
    blob, toc = b"", b""
    for name, typecode, data in entries:
        nm = name.encode() + b"\x00"
        toc += struct.pack(">IIII", 18 + len(nm), len(blob), len(data), len(data))
        toc += struct.pack("BB", 0, ord(typecode)) + nm
        blob += data
    package_length = len(blob) + len(toc) + 88
    cookie = (PYI_MAGIC + struct.pack(">IIII", package_length, len(blob), len(toc), pyver)
              + b"libpython3.so".ljust(64, b"\x00"))
    return b"\x7fELF" + b"\x00" * 60 + blob + toc + cookie


def pyz(magic=PYC_312) -> bytes:
    return b"PYZ\x00" + magic + b"\x00" * 16


# The program a stub carries: an ELF head and a flag constant, only ever compressed inside the stub.
INNER = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"the inner program " + FLAG.encode() + b"\x00" * 8


def stub_elf(stream: bytes, pad: int = 64) -> bytes:
    """A native stub: an ELF head, padding, one embedded stream (at offset 4 + pad), trailing bytes."""
    return b"\x7fELF" + b"\x00" * pad + stream + b"\x00" * 16


def ap32_bytes(payload: bytes, original: bytes) -> bytes:
    """An AP32 safe wrapper around an aPLib stream: header size, sizes and both CRC32s."""
    return b"AP32" + struct.pack("<IIIII", 24, len(payload), zlib.crc32(payload) & 0xFFFFFFFF,
                                 len(original), zlib.crc32(original) & 0xFFFFFFFF) + payload


@pytest.fixture(params=[("zlib", zlib.compress), ("gzip", lambda b: gzip.compress(b, mtime=0)),
                        ("bzip2", bz2.compress), ("xz", lambda b: lzma.compress(b, format=lzma.FORMAT_XZ))],
                ids=lambda p: p[0])
def stream_format(request):
    return request.param


class CountingPacker:
    """The real packer_unpack module, recording each full decode: (offset, format, max_output)."""

    def __init__(self, real):
        self.real, self.calls = real, []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def decompress_carved(self, data, candidate, *, max_output):
        self.calls.append((candidate.offset, candidate.format, max_output))
        return self.real.decompress_carved(data, candidate, max_output=max_output)


@pytest.fixture(autouse=True)
def _fresh_carve_memo():
    sr._CARVED[:] = [None, {}]        # embedded_images keeps its last answer: none carries between tests


# ================================================================== sniffing
def test_sniff_pyc():
    assert sr.is_pyc(pyc_bytes()) and sr.sniff(pyc_bytes()) == "pyc"


def test_sniff_pyc_needs_a_whole_header():
    # a known magic, but shorter than the 16-byte header: not a pyc. Exactly 16 bytes is one.
    assert not sr.is_pyc(PYC_312)
    assert not sr.is_pyc(PYC_312 + b"\x00" * 4)
    assert not sr.is_pyc(PYC_312 + b"\x00" * 11)
    assert sr.is_pyc(PYC_312 + b"\x00" * 12)


def test_sniff_rejects_crlf_text_that_is_not_a_pyc_magic():
    # b'\r\n' at offset 2 is in every Windows text file with a two-character first line.
    for text in (b"hi\r\nthis is a note, not bytecode\r\n", b"OK\r\n" + b"plain text " * 4):
        assert len(text) >= 16 and text[2:4] == b"\r\n"
        assert not sr.is_pyc(text) and sr.sniff(text) is None


def test_sniff_accepts_old_and_new_cpython_magics():
    assert sr.is_pyc(bytes.fromhex("03f30d0a") + b"\x00" * 20)     # 2.7 (62211)
    assert sr.is_pyc(bytes.fromhex("550d0d0a") + b"\x00" * 20)     # 3.8 (3413)
    assert sr.is_pyc(bytes.fromhex("f30d0d0a") + b"\x00" * 20)     # 3.13 (3571)
    assert not sr.is_pyc(bytes.fromhex("00100d0a") + b"\x00" * 20)  # 4096: not a CPython magic word


def test_sniff_java_class():
    assert sr.is_java_class(class_bytes()) and sr.sniff(class_bytes()) == "jvm_class"


def test_sniff_java_class_major_version_bounds():
    assert sr.is_java_class(class_bytes(major=45))          # JDK 1.1, the lowest class version
    assert not sr.is_java_class(class_bytes(major=44))
    assert sr.is_java_class(class_bytes(major=255))
    assert not sr.is_java_class(class_bytes(major=256))


def test_sniff_tells_a_java_class_from_a_fat_macho():
    # Both start CA FE BA BE; only the class has a plausible major_version. This is the whole point of
    # is_java_class -- a fat Mach-O must NOT be routed to a JVM decompiler.
    assert sr.is_java_class(class_bytes())
    assert not sr.is_java_class(fat_macho_bytes())
    assert sr.sniff(fat_macho_bytes()) is None


def test_sniff_jar_vs_plain_zip():
    assert sr.is_jar(jar_bytes()) and sr.sniff(jar_bytes()) == "jvm_jar"
    assert not sr.is_jar(plain_zip_bytes()) and sr.sniff(plain_zip_bytes()) is None


def test_sniff_jar_goes_by_entry_names_not_raw_bytes():
    # An EPUB / ODT has META-INF/, an APK has META-INF/MANIFEST.MF and classes.dex, and a text member
    # may mention "Main.class": none of them is a jar, because none has a .class ENTRY.
    epub = zip_bytes({"mimetype": b"application/epub+zip", "META-INF/container.xml": b"<container/>"})
    apk = zip_bytes({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "classes.dex": b"dex\n035\x00"})
    talks = zip_bytes({"readme.txt": b"run java -cp . Main.class and look in META-INF/"})
    for z in (epub, apk, talks):
        assert not sr.is_jar(z) and sr.sniff(z) is None


def test_sniff_jar_with_a_damaged_central_directory_reads_local_headers():
    name = b"Main.class"
    body = class_bytes()
    local = (b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 8 + b"\x00" * 4
             + struct.pack("<IIHH", len(body), len(body), len(name), 0) + name + body)
    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(io.BytesIO(local))                   # no central directory at all
    assert sr.zip_names(local) == ["Main.class"] and sr.is_jar(local)


def test_sniff_jar_local_headers_step_over_each_members_body():
    # No central directory, and the .class entry is the SECOND local header: reaching it means
    # stepping over the first entry's name, extra field and body.
    def local(name: bytes, body: bytes, extra: bytes = b"") -> bytes:
        return (b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 8 + b"\x00" * 4
                + struct.pack("<IIHH", len(body), len(body), len(name), len(extra)) + name + extra + body)
    damaged = local(b"notes.txt", b"hello, this body is not a header", b"\xca\xfe\x00\x00") \
        + local(b"pkg/Main.class", class_bytes())
    with pytest.raises(zipfile.BadZipFile):
        zipfile.ZipFile(io.BytesIO(damaged))
    assert sr.zip_names(damaged) == ["notes.txt", "pkg/Main.class"]
    assert sr.is_jar(damaged) and sr.sniff(damaged) == "jvm_jar"


def test_sniff_a_upx_packed_fat_macho_is_native():
    # A universal Mach-O shares CA FE BA BE with a Java class; it is native, so a UPX-packed one is
    # unpacked like a thin Mach-O. The class major_version / nfat_arch split decides, both ways.
    fat = fat_macho_bytes() + b"UPX!" + b"\x00" * 8
    assert sr.is_fat_macho(fat) and sr.is_upx_packed(fat) and sr.sniff(fat) == "upx"
    assert sr.sniff(fat_macho_bytes()) is None                # not packed: nothing to recover
    assert sr.is_fat_macho(fat_macho_bytes(nfat=1)) and sr.is_fat_macho(fat_macho_bytes(nfat=44))
    assert not sr.is_fat_macho(fat_macho_bytes(nfat=0))
    assert not sr.is_fat_macho(fat_macho_bytes(nfat=45)) and not sr.is_fat_macho(class_bytes())
    assert not sr.is_fat_macho(b"\xca\xfe\xba\xbe\x00\x00\x02")   # no whole nfat_arch field
    assert not sr.is_upx_packed(class_bytes() + b"UPX!")      # a class file that mentions UPX! is not native
    assert sr.is_pyinstaller(fat_macho_bytes() + PYI_MAGIC)


def test_sniff_upx_packed():
    assert sr.is_upx_packed(upx_elf_bytes()) and sr.sniff(upx_elf_bytes()) == "upx"
    assert not sr.is_upx_packed(b"\x7fELF" + b"\x00" * 80)   # ELF without the UPX! marker
    assert sr.is_upx_packed(b"MZ" + b"\x00" * 40 + b"UPX!" + b"\x00" * 8)


def test_sniff_upx_marker_in_a_non_native_file_is_not_packed():
    text = b"The packer writes UPX! into the image. " * 2
    assert b"UPX!" in text
    assert not sr.is_upx_packed(text) and sr.sniff(text) is None


def test_sniff_pyinstaller_before_upx():
    exe = pyi_bytes([("main", "s", CODE + b"UPX!")])
    assert sr.is_pyinstaller(exe) and sr.sniff(exe) == "pyinstaller"
    assert not sr.is_pyinstaller(PYI_MAGIC * 4)              # the cookie magic in a non-native file


# ================================================================== python recovery
def test_recover_python_uses_pycdc_first(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n')
    fake.responses["decompyle3"] = FakeResult(stdout=b'should_not_be_used = 1\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")
    assert rec.ok and not rec.partial and rec.tool == "pycdc" and rec.outputs == {"mod.py": b'x = 1\n'}
    assert [c[0] for c in fake.calls] == ["pycdc"]          # decompyle3 never tried on pycdc success
    assert fake.calls[0][1] == ["{in}"] and fake.calls[0][2] == ["input.pyc"]


def test_recover_python_falls_back_to_decompyle3(fake):
    # pycdc ran but produced only a banner (no code): fall back to decompyle3.
    fake.responses["pycdc"] = FakeResult(code=1, stdout=b'# Could not decompile\n', stderr=b'bad bytecode')
    fake.responses["decompyle3"] = FakeResult(stdout=b'y = 2\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")
    assert rec.ok and not rec.partial and rec.tool == "decompyle3" and rec.outputs == {"mod.py": b'y = 2\n'}
    assert [c[0] for c in fake.calls] == ["pycdc", "decompyle3"]


def test_recover_python_source_with_a_failing_exit_is_not_clean(fake):
    # pycdc printed code but exited 1: that is not a clean recovery, so the fallback is tried and wins.
    fake.responses["pycdc"] = FakeResult(code=1, stdout=b'x = 1\n', stderr=b'Error decompyling input.pyc')
    fake.responses["decompyle3"] = FakeResult(stdout=b'y = 2\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")
    assert rec.ok and not rec.partial and rec.tool == "decompyle3" and rec.outputs == {"mod.py": b'y = 2\n'}


def test_recover_python_incomplete_pycdc_tries_the_fallback(fake):
    # The shape pycdc gives on bytecode it only half understands: exit 0, some source, the incomplete
    # banner on stdout and "Unsupported opcode" on stderr. Not a clean recovery: decompyle3 is tried.
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n# WARNING: Decompyle incomplete\n',
                                         stderr=b'Unsupported opcode: RESUME (243)\n')
    fake.responses["decompyle3"] = FakeResult(stdout=b'x = 1\ny = 2\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")
    assert [c[0] for c in fake.calls] == ["pycdc", "decompyle3"]
    assert rec.ok and not rec.partial and rec.tool == "decompyle3"
    assert rec.outputs == {"mod.py": b'x = 1\ny = 2\n'}


def test_recover_python_incomplete_keeps_the_partial_source_and_adds_the_disassembly(fake):
    partial = b'x = 1\n# WARNING: Decompyle incomplete\n'
    fake.responses["pycdc"] = FakeResult(stdout=partial, stderr=b'Unsupported opcode: RESUME (243)\n')
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b'Unsupported Python version, 3.12.0')
    fake.responses["pycdas"] = FakeResult(stdout=b'[Code]\n    File Name: mod.py\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")
    assert [c[0] for c in fake.calls] == ["pycdc", "decompyle3", "pycdas"]
    assert rec.ok and rec.partial and not rec.blocked
    assert rec.tool == "pycdc+pycdas"
    assert rec.outputs == {"mod.py": partial, "mod.pycdas.txt": b'[Code]\n    File Name: mod.py\n'}
    assert "incomplete" in rec.note and "Unsupported Python version" in rec.note


def test_recover_python_unsupported_opcode_on_stderr_alone_is_partial(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n', stderr=b'Unsupported opcode: CACHE (0)\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")        # decompyle3 and pycdas: sandbox down
    assert rec.ok and rec.partial and rec.tool == "pycdc" and rec.outputs == {"mod.py": b'x = 1\n'}


def test_recover_python_disassembly_is_the_last_resort(fake):
    fake.responses["pycdc"] = FakeResult(code=1, stderr=b'Error loading file input.pyc: Bad MAGIC!')
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b'unsupported version')
    fake.responses["pycdas"] = FakeResult(stdout=b'[Code]\n')
    rec = sr.recover_python(pyc_bytes(), name="mod")
    assert rec.ok and rec.partial and rec.tool == "pycdas" and rec.outputs == {"mod.pycdas.txt": b'[Code]\n'}


def test_recover_python_pycdas_is_not_run_after_clean_source(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n')
    fake.responses["pycdas"] = FakeResult(stdout=b'[Code]\n')
    sr.recover_python(pyc_bytes())
    assert "pycdas" not in [c[0] for c in fake.calls]


def test_recover_python_comment_only_output_is_not_success(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'# Source Generated with Decompyle++\n')
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b'unsupported version')
    fake.responses["pycdas"] = FakeResult(code=1, stderr=b'Bad MAGIC!')
    rec = sr.recover_python(pyc_bytes())
    assert not rec.ok and not rec.blocked and "no source" in rec.note and "no disassembly" in rec.note


def test_recover_python_blocked_when_sandbox_down(fake):
    # No tool configured -> all raise SandboxDown -> blocked with the named rebuild/start step.
    rec = sr.recover_python(pyc_bytes())
    assert rec.blocked and not rec.ok
    assert "sandbox down" in rec.note and "Dockerfile.2" in rec.note


def test_recover_python_one_tool_down_one_failed_is_not_blocked(fake):
    # pycdc is missing from the image (down) but decompyle3 RAN and failed: the sandbox is up, so this
    # is a failed recovery, not a blocked one.
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b'unsupported version')
    rec = sr.recover_python(pyc_bytes())
    assert not rec.ok and not rec.blocked
    assert "decompyle3 produced no source" in rec.note and "pycdc: pycdc is not in" in rec.note


def test_recover_python_names_a_denied_docker_socket(fake):
    # Under intake's macOS network guard the docker CLI is refused its socket. The note must say that
    # and how to run the engine, not send the operator off to rebuild an image that is fine.
    for tool in ("pycdc", "decompyle3", "pycdas"):
        fake.responses[tool] = fake.SandboxDown(DENIED)
    rec = sr.recover_python(pyc_bytes())
    assert rec.blocked
    assert "network guard" in rec.note and "python -m ctf run binary.sandbox_recover" in rec.note
    assert "Dockerfile.2" not in rec.note


def test_guard_denied_only_for_a_refused_docker_socket():
    assert sr.guard_denied(DENIED)
    assert not sr.guard_denied("not started; run tools/sandbox.py start first")
    assert not sr.guard_denied("pycdc is not in csctf-sandbox:2")
    assert not sr.guard_denied("permission denied reading the drop folder")


def test_recover_python_a_refused_tool_is_reported_not_swallowed(fake):
    fake.responses["pycdc"] = ValueError("pycdc is not a sandbox tool (upx, 7z)")
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b'unsupported version')
    fake.responses["pycdas"] = FakeResult(code=1)
    rec = sr.recover_python(pyc_bytes())
    assert not rec.ok and not rec.blocked and "pycdc is not a sandbox tool" in rec.note


def test_recover_python_start_is_passed_through(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n')
    sr.recover_python(pyc_bytes())
    sr.recover_python(pyc_bytes(), start=False)
    assert fake.starts == [True, False]


def test_recover_python_gives_a_tool_no_more_than_the_budget_has_left(fake):
    clock = StepClock()
    end = clock() + 50.0
    fake.on_run = clock.advance                              # each tool takes all the time it was given
    fake.responses["pycdc"] = FakeResult(code=124)
    fake.responses["decompyle3"] = FakeResult(code=124)
    rec = sr.recover_python(pyc_bytes(), timeout=40.0, left=lambda: end - clock())
    # pycdc gets its 40 s, decompyle3 only the 10 s left, pycdas is not started with nothing left.
    assert [(c[0], c[3]) for c in fake.calls] == [("pycdc", 40.0), ("decompyle3", 10.0)]
    assert not rec.ok and "pycdas not run: the time budget is spent" in rec.note


def test_recover_python_disassembly_gets_the_shorter_of_its_own_limit_and_the_callers(fake):
    # pycdas only lists the bytecode: it is held to DISASM_TIMEOUT even when the decompilers get more,
    # and to the caller's timeout when that is the smaller one.
    for tool in ("pycdc", "decompyle3"):
        fake.responses[tool] = FakeResult(code=1, stderr=b"unsupported version")
    fake.responses["pycdas"] = FakeResult(stdout=b"[Code]\n")
    assert sr.DISASM_TIMEOUT < 60.0
    sr.recover_python(pyc_bytes(), timeout=60.0)
    assert [(c[0], c[3]) for c in fake.calls] == [("pycdc", 60.0), ("decompyle3", 60.0),
                                                  ("pycdas", sr.DISASM_TIMEOUT)]
    fake.calls.clear()
    sr.recover_python(pyc_bytes(), timeout=7.5)
    assert [(c[0], c[3]) for c in fake.calls] == [("pycdc", 7.5), ("decompyle3", 7.5), ("pycdas", 7.5)]


# ================================================================== jvm recovery
def test_recover_jvm_class_uses_cfr_stdout(fake):
    fake.responses["cfr"] = FakeResult(stdout=b'/*\n * Decompiled with CFR 0.152.\n */\nclass Main { int f; }\n')
    rec = sr.recover_jvm(class_bytes(), name="Main")
    assert rec.ok and not rec.partial and rec.tool == "cfr" and rec.kind == "jvm_class"
    assert set(rec.outputs) == {"Main.java"}
    # a single class is decompiled to stdout, not into an output directory
    assert fake.calls[0][1] == ["{in}"] and fake.calls[0][2] == ["Main.class"]


def test_recover_jvm_cfr_banner_alone_is_not_source(fake):
    # CFR prints its block-comment banner even when it decompiles nothing: that is not recovered code.
    fake.responses["cfr"] = FakeResult(stdout=b'/*\n * Decompiled with CFR 0.152.\n */\n')
    fake.responses["vineflower"] = FakeResult(files={"Main.java": b"class Main{}"})
    rec = sr.recover_jvm(class_bytes(), name="Main")
    assert rec.ok and rec.tool == "vineflower" and rec.outputs == {"Main.java": b"class Main{}"}


def test_recover_jvm_jar_collects_java_members(fake):
    files = {"a/A.java": b"class A{}", "a/B.java": b"class B{}", "summary.txt": b"skip"}
    fake.responses["cfr"] = FakeResult(files=files)
    rec = sr.recover_jvm(jar_bytes())
    assert rec.ok and rec.kind == "jvm_jar"
    assert set(rec.outputs) == {"a/A.java", "a/B.java"}      # .txt dropped
    assert fake.calls[0][1] == ["{in}", "--outputpath", "{out}"]   # jar -> output-directory mode
    assert fake.calls[0][2] == ["input.jar"]


def test_recover_jvm_jar_falls_back_to_vineflower_with_in_and_out(fake):
    fake.responses["cfr"] = FakeResult(code=1, stderr=b'cfr could not read the jar')
    fake.responses["vineflower"] = FakeResult(files={"a/A.java": b"class A{}"})
    rec = sr.recover_jvm(jar_bytes())
    assert rec.ok and rec.tool == "vineflower" and rec.outputs == {"a/A.java": b"class A{}"}
    assert fake.calls[1] == ("vineflower", ["{in}", "{out}"], ["input.jar"], sr.JVM_TIMEOUT)


def test_recover_jvm_reads_java_out_of_a_source_archive(fake):
    # Vineflower can save a jar's sources as a jar of .java in the out folder instead of loose files.
    archive = zip_bytes({"a/A.java": b"class A{}", "META-INF/MANIFEST.MF": b"x", "b/B.java": b"class B{}"})
    fake.responses["cfr"] = FakeResult(code=1, stderr=b'cfr could not read the jar')
    fake.responses["vineflower"] = FakeResult(files={"input.jar": archive})
    rec = sr.recover_jvm(jar_bytes())
    assert rec.ok and rec.tool == "vineflower"
    assert rec.outputs == {"a/A.java": b"class A{}", "b/B.java": b"class B{}"}


def test_java_members_bounds_what_it_reads_from_a_source_archive(monkeypatch):
    monkeypatch.setattr(sr, "MAX_MEMBER_BYTES", 16)
    archive = zip_bytes({"Big.java": b"x" * 17, "Ok.java": b"class Ok{}"})
    assert sr._java_members({"out.jar": archive}) == {"Ok.java": b"class Ok{}"}


def test_java_members_bounds_the_total_it_reads_from_a_source_archive(monkeypatch):
    # Each member is under MAX_MEMBER_BYTES; together they are held to MAX_OUTPUT_BYTES. A member that
    # would take the total over is left out, and a later one that still fits (exactly) is kept.
    monkeypatch.setattr(sr, "MAX_OUTPUT_BYTES", 24)
    archive = zip_bytes({"A.java": b"class A{} ", "B.java": b"class B{} ", "C.java": b"class C{} ",
                         "D.java": b"int;"})
    assert sr._java_members({"out.jar": archive}) == {"A.java": b"class A{} ", "B.java": b"class B{} ",
                                                      "D.java": b"int;"}


def test_recover_jvm_falls_back_to_vineflower(fake):
    fake.responses["cfr"] = FakeResult(code=1, stderr=b'cfr parse error')
    fake.responses["vineflower"] = FakeResult(files={"Main.java": b"class Main{}"})
    rec = sr.recover_jvm(class_bytes(), name="Main")
    assert rec.ok and rec.tool == "vineflower"
    assert [c[0] for c in fake.calls] == ["cfr", "vineflower"]
    assert fake.calls[1][1] == ["{in}", "{out}"]


def test_recover_jvm_partial_cfr_source_is_kept_only_without_a_cleaner_one(fake):
    partial = b'class Main {\n    /* This method has failed to decompile. */\n    void f() {}\n}\n'
    fake.responses["cfr"] = FakeResult(stdout=partial)
    rec = sr.recover_jvm(class_bytes(), name="Main")        # vineflower: sandbox down
    assert rec.ok and rec.partial and rec.tool == "cfr" and rec.outputs == {"Main.java": partial}
    fake.responses["vineflower"] = FakeResult(files={"Main.java": b"class Main{ void f(){} }"})
    rec = sr.recover_jvm(class_bytes(), name="Main")
    assert rec.ok and not rec.partial and rec.tool == "vineflower"


def test_recover_jvm_blocked_when_sandbox_down(fake):
    rec = sr.recover_jvm(class_bytes())
    assert rec.blocked and "sandbox down" in rec.note


def test_recover_jvm_one_tool_down_one_failed_is_not_blocked(fake):
    # cfr is missing from the image (down) but vineflower RAN and failed: failed, not blocked.
    fake.responses["vineflower"] = FakeResult(code=1, stderr=b'not a class file')
    rec = sr.recover_jvm(class_bytes(), name="Main")
    assert not rec.ok and not rec.blocked
    assert "vineflower produced no .java" in rec.note and "cfr: cfr is not in" in rec.note


def test_recover_jvm_a_refused_tool_is_reported_not_swallowed(fake):
    fake.responses["cfr"] = ValueError("cfr is not a sandbox tool (upx, 7z)")
    rec = sr.recover_jvm(class_bytes(), name="Main")        # vineflower: sandbox down
    assert not rec.ok and not rec.blocked and "cfr is not a sandbox tool" in rec.note


def test_recover_jvm_timeout_is_not_success(fake):
    fake.responses["cfr"] = FakeResult(code=124)
    fake.responses["vineflower"] = FakeResult(code=124)
    rec = sr.recover_jvm(class_bytes())
    assert not rec.ok and not rec.blocked and "timed out" in rec.note


# ================================================================== upx unpack
def test_unpack_upx_success(fake):
    fake.upx = (b"\x7fELFunpacked", "unpacked by upx -d to 13 bytes in the sandbox")
    rec = sr.unpack_upx(upx_elf_bytes(), name="bin")
    assert rec.ok and rec.tool == "upx" and rec.outputs == {"bin": b"\x7fELFunpacked"}
    assert fake.upx_calls == [(upx_elf_bytes(), sr.UPX_TIMEOUT)] and fake.starts == [True]


def test_unpack_upx_sandbox_down_is_blocked(fake):
    fake.upx = (None, "sandbox down: not started: the packed image is not read")
    rec = sr.unpack_upx(upx_elf_bytes())
    assert rec.blocked and "sandbox down" in rec.note and "Dockerfile.2" in rec.note


def test_unpack_upx_names_a_denied_docker_socket(fake):
    fake.upx = (None, f"sandbox down: {DENIED}: the packed image is not read")
    rec = sr.unpack_upx(upx_elf_bytes())
    assert rec.blocked and "network guard" in rec.note and "Dockerfile.2" not in rec.note


def test_unpack_upx_failure_is_not_blocked(fake):
    fake.upx = (None, "upx -d failed in the sandbox (NotPacked)")
    rec = sr.unpack_upx(upx_elf_bytes())
    assert not rec.ok and not rec.blocked


# ================================================================== pyinstaller
def test_recover_pyinstaller_rebuilds_the_script_pyc_and_decompiles_it(fake):
    exe = pyi_bytes([("pyiboot01_bootstrap", "s", CODE), ("pyi_rth_inspect", "s", CODE),
                     ("main", "s", CODE + b"main"), ("PYZ-00.pyz", "z", pyz(bytes.fromhex("a70d0d0a")))],
                    pyver=312)
    fake.responses["pycdc"] = FakeResult(stdout=b'print("hi")\n')
    rec = sr.recover_pyinstaller(exe, name="app")
    assert rec.ok and not rec.partial and rec.kind == "pyinstaller"
    assert rec.tool == "pyinstaller_extract+pycdc"
    # PyInstaller's own bootstrap and runtime hooks are not sent to the decompiler; the script is, as
    # a .pyc under the magic the PYZ member records (3.11 here, not the cookie's 3.12) and a zeroed
    # 16-byte header.
    want_pyc = bytes.fromhex("a70d0d0a") + b"\x00" * 12 + CODE + b"main"
    assert fake.bodies == [("pycdc", want_pyc)]
    assert rec.outputs == {"main.pyc": want_pyc, "main.py": b'print("hi")\n'}


def test_recover_pyinstaller_takes_the_magic_from_the_python_version_without_a_pyz(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n')
    sr.recover_pyinstaller(pyi_bytes([("main", "s", CODE)], pyver=38))
    assert fake.bodies[0][1] == bytes.fromhex("550d0d0a") + b"\x00" * 12 + CODE      # 3.8, 16-byte header
    sr.recover_pyinstaller(pyi_bytes([("main", "s", CODE)], pyver=27))
    assert fake.bodies[1][1] == bytes.fromhex("03f30d0a") + b"\x00" * 4 + CODE       # 2.7, 8-byte header
    sr.recover_pyinstaller(pyi_bytes([("main", "s", CODE)], pyver=36))
    assert fake.bodies[2][1] == bytes.fromhex("330d0d0a") + b"\x00" * 8 + CODE       # 3.6, 12-byte header


def test_recover_pyinstaller_leaves_an_entry_with_a_header_alone(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n')
    whole = pyc_bytes(CODE)
    sr.recover_pyinstaller(pyi_bytes([("main", "s", whole)], pyver=312))
    assert fake.bodies[0][1] == whole


def test_recover_pyinstaller_unknown_python_and_no_pyz_is_a_named_failure(fake):
    rec = sr.recover_pyinstaller(pyi_bytes([("main", "s", CODE)], pyver=399), name="app")
    assert not rec.ok and not rec.blocked and "Python 399" in rec.note and "magic" in rec.note
    assert fake.calls == []


def test_recover_pyinstaller_without_a_script_is_a_named_failure(fake):
    rec = sr.recover_pyinstaller(pyi_bytes([("pyiboot01_bootstrap", "s", CODE), ("lib.so", "b", b"\x7fELF")]))
    assert not rec.ok and "no script entry" in rec.note and fake.calls == []


def test_recover_pyinstaller_broken_archive_is_a_named_failure(fake):
    broken = b"\x7fELF" + b"\x00" * 64 + PYI_MAGIC + b"\xff" * 80
    assert sr.sniff(broken) == "pyinstaller"
    rec = sr.recover_pyinstaller(broken, name="app")
    assert not rec.ok and not rec.blocked and "could not be read" in rec.note


def test_recover_pyinstaller_sandbox_down_is_blocked_but_keeps_the_pyc(fake):
    rec = sr.recover_pyinstaller(pyi_bytes([("main", "s", CODE)], pyver=312))
    assert rec.blocked and not rec.ok
    assert rec.outputs == {"main.pyc": PYC_312 + b"\x00" * 12 + CODE}
    assert "sandbox down" in rec.note


def test_recover_pyinstaller_some_scripts_recovered_is_partial(fake):
    def pycdc(tool, args, inputs):
        return FakeResult(stdout=b'x = 1\n') if inputs[0][1].endswith(b"good") else FakeResult(code=1)
    fake.responses["pycdc"] = pycdc
    fake.responses["decompyle3"] = FakeResult(code=1)
    fake.responses["pycdas"] = FakeResult(code=1)
    rec = sr.recover_pyinstaller(pyi_bytes([("a", "s", CODE + b"good"), ("b", "s", CODE + b"bad")]))
    assert rec.ok and rec.partial and "a.py" in rec.outputs and "b.py" not in rec.outputs
    assert "b: " in rec.note


def test_recover_pyinstaller_caps_the_scripts_it_recovers_and_says_so(fake):
    # 17 script entries, every one decompiles cleanly: 16 are recovered, the 17th is named as left
    # out, and the recovery is partial -- never reported as complete.
    assert sr.MAX_PYI_SCRIPTS == 16
    fake.responses["pycdc"] = FakeResult(stdout=b"x = 1\n")
    exe = pyi_bytes([(f"s{i:02d}", "s", CODE + bytes([i])) for i in range(17)])
    rec = sr.recover_pyinstaller(exe, name="app")
    assert [c[0] for c in fake.calls] == ["pycdc"] * 16
    assert [body[-1] for _tool, body in fake.bodies] == list(range(16))
    assert rec.ok and rec.partial and not rec.blocked
    assert "1 more script entries not recovered (over MAX_PYI_SCRIPTS=16)" in rec.note
    assert "s15.py" in rec.outputs and "s16.pyc" not in rec.outputs and "s16.py" not in rec.outputs
    # exactly at the cap nothing is left out, so a clean recovery of all 16 is not partial
    fake.calls.clear()
    rec = sr.recover_pyinstaller(pyi_bytes([(f"s{i:02d}", "s", CODE + bytes([i])) for i in range(16)]))
    assert len(fake.calls) == 16 and rec.ok and not rec.partial and "more script entries" not in rec.note


def test_solve_pyinstaller_over_the_script_cap_is_not_a_clean_none(fake, tmp_path):
    fake.responses["pycdc"] = FakeResult(stdout=b"x = 1\n")
    _write(tmp_path, "files/app", pyi_bytes([(f"s{i:02d}", "s", CODE + bytes([i])) for i in range(17)]))
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and "1 more script entries not recovered" in res.notes


# ================================================================== recover() dispatch
def test_recover_dispatch_rejects_unknown():
    with pytest.raises(sr.NotRecoverable):
        sr.recover(b"\x00" * 64, name="plain")
    assert issubclass(sr.NotRecoverable, ValueError)


def test_recover_dispatch_routes_each_kind(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b"z = 3\n")
    fake.responses["cfr"] = FakeResult(stdout=b"class Main {}\n", files={"A.java": b"class A{}"})
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    assert sr.recover(pyc_bytes()).kind == "pyc"
    assert sr.recover(class_bytes()).kind == "jvm_class"
    assert sr.recover(jar_bytes()).kind == "jvm_jar"
    assert sr.recover(pyi_bytes([("main", "s", CODE)])).kind == "pyinstaller"
    rec = sr.recover(upx_elf_bytes(), name="bin")
    assert rec.kind == "upx" and rec.ok and rec.outputs == {"bin": b"\x7fELFunpacked"}
    assert len(fake.upx_calls) == 1
    assert sr.recover(stub_elf(zlib.compress(INNER))).kind == "stub"
    assert len(fake.upx_calls) == 1                          # a stub is unpacked in memory, not by upx


def test_recover_dispatch_passes_the_timeout_or_each_kinds_default(fake):
    fake.responses["pycdc"] = FakeResult(stdout=b"z = 3\n")
    fake.responses["cfr"] = FakeResult(stdout=b"class Main {}\n")
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    sr.recover(pyc_bytes())
    sr.recover(pyc_bytes(), timeout=7.5)
    sr.recover(class_bytes())
    sr.recover(class_bytes(), timeout=8.5)
    sr.recover(upx_elf_bytes())
    sr.recover(upx_elf_bytes(), timeout=9.5)
    assert [c[3] for c in fake.calls] == [sr.PY_TIMEOUT, 7.5, sr.JVM_TIMEOUT, 8.5]
    assert [c[1] for c in fake.upx_calls] == [sr.UPX_TIMEOUT, 9.5]
    assert len({sr.PY_TIMEOUT, sr.JVM_TIMEOUT, sr.UPX_TIMEOUT, 7.5, 8.5, 9.5}) == 6


# ================================================================== the intake engine
def _write(challenge_dir: Path, rel: str, data: bytes) -> Path:
    p = challenge_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def _outputs(challenge_dir: Path) -> list[str]:
    base = challenge_dir / "recon" / "recover"
    return sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()) if base.is_dir() else []


def test_solve_candidate_from_a_recovered_pyc(fake, tmp_path):
    fake.responses["pycdc"] = FakeResult(stdout=f'FLAG = "{FLAG}"\n'.encode())
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == (FLAG,)
    assert len(res.evidence) == 1
    ev = res.evidence[0]
    assert ev.kind == "decompile" and "app.pyc" in ev.detail and "pycdc" in ev.detail
    # the evidence names the file that was written, relative to the challenge folder
    assert re.fullmatch(r"recon/recover/app\.pyc-[0-9a-f]{8}/app\.py", ev.path)
    assert FLAG.encode() in (tmp_path / ev.path).read_bytes()


def test_solve_none_when_recovered_without_flag(fake, tmp_path):
    fake.responses["cfr"] = FakeResult(stdout=b"class Main { int x; }\n")
    _write(tmp_path, "files/Main.class", class_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "none" and not res.flags
    assert "files/Main.class (jvm_class by cfr)" in res.notes
    assert (tmp_path / res.evidence[0].path).read_bytes() == b"class Main { int x; }\n"


def test_solve_blocked_when_sandbox_down_for_all(fake, tmp_path):
    # no tool configured: every file is blocked (sandbox down). Loud, named, never silently green.
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "blocked" and "sandbox" in res.notes.lower()
    assert "Dockerfile.2" in res.notes


def test_solve_never_starts_a_container(fake, decomp, tmp_path):
    # intake is a timed path: every sandbox call from solve() carries start=False.
    fake.responses["pycdc"] = FakeResult(stdout=b"ok = 1\n")
    fake.responses["cfr"] = FakeResult(stdout=b"class Main {}\n")
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    _write(tmp_path, "app.pyc", pyc_bytes())
    _write(tmp_path, "Main.class", class_bytes())
    _write(tmp_path, "packed", upx_elf_bytes())
    sr.solve(tmp_path, CSCTF)
    assert len(fake.starts) == 3 and not any(fake.starts)


def test_solve_blocked_names_the_network_guard_when_docker_is_denied(fake, tmp_path):
    for tool in ("pycdc", "decompyle3", "pycdas"):
        fake.responses[tool] = fake.SandboxDown(DENIED)
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "network guard" in res.notes and "python -m ctf run binary.sandbox_recover" in res.notes
    assert "Dockerfile.2" not in res.notes


def test_solve_unsure_when_some_recover_and_some_blocked(fake, tmp_path):
    fake.responses["pycdc"] = FakeResult(stdout=b"ok = 1\n")   # the pyc recovers; the class has no tool
    _write(tmp_path, "app.pyc", pyc_bytes())
    _write(tmp_path, "Main.class", class_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "recovered" in res.notes and "sandbox down" in res.notes


def test_solve_unsure_when_a_tool_ran_and_recovered_nothing(fake, tmp_path):
    # the sandbox is up and every decompiler failed: that is not a clean "none".
    for tool in ("pycdc", "decompyle3", "pycdas"):
        fake.responses[tool] = FakeResult(code=1, stderr=b"bad magic")
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and "recovered nothing" in res.notes and "app.pyc" in res.notes
    assert not res.evidence


def test_solve_unsure_when_one_file_failed_and_one_was_blocked(fake, tmp_path):
    for tool in ("pycdc", "decompyle3", "pycdas"):
        fake.responses[tool] = FakeResult(code=1, stderr=b"bad magic")
    _write(tmp_path, "app.pyc", pyc_bytes())                  # fails in a sandbox that is up
    _write(tmp_path, "Main.class", class_bytes())             # cfr / vineflower: down
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "could not recover: app.pyc" in res.notes and "sandbox down for: Main.class" in res.notes


def test_solve_unsure_for_a_partial_decompile(fake, tmp_path):
    fake.responses["pycdc"] = FakeResult(stdout=b'x = 1\n# WARNING: Decompyle incomplete\n',
                                         stderr=b'Unsupported opcode: RESUME (243)\n')
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b"unsupported version")
    fake.responses["pycdas"] = FakeResult(stdout=b"[Code]\n")
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and "recovered in part" in res.notes and "incomplete" in res.notes
    assert [Path(e.path).name for e in res.evidence] == ["app.py", "app.pycdas.txt"]
    assert all((tmp_path / e.path).is_file() for e in res.evidence)


def test_solve_unsure_when_one_file_is_clean_and_one_is_partial(fake, tmp_path):
    def pycdc(tool, args, inputs):
        if inputs[0][1].endswith(b"half"):
            return FakeResult(stdout=b'x = 1\n# WARNING: Decompyle incomplete\n')
        return FakeResult(stdout=b'x = 1\n')
    fake.responses["pycdc"] = pycdc
    fake.responses["decompyle3"] = FakeResult(code=1, stderr=b"unsupported version")
    fake.responses["pycdas"] = FakeResult(code=1)
    _write(tmp_path, "good.pyc", pyc_bytes(b"\x00" * 16 + b"good"))
    _write(tmp_path, "half.pyc", pyc_bytes(b"\x00" * 16 + b"half"))
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "recovered good.pyc (pyc by pycdc)" in res.notes and "recovered in part: half.pyc" in res.notes


def test_solve_candidate_from_a_partial_decompile(fake, tmp_path):
    fake.responses["pycdc"] = FakeResult(stdout=f'F = "{FLAG}"\n# WARNING: Decompyle incomplete\n'.encode())
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == (FLAG,) and "recovered in part" in res.notes


def test_solve_none_when_nothing_recoverable(fake, tmp_path):
    _write(tmp_path, "readme.txt", b"just text, nothing to recover")
    _write(tmp_path, "notes.txt", b"hi\r\nthis Windows note is not bytecode\r\n")
    _write(tmp_path, "book.epub", zip_bytes({"META-INF/container.xml": b"<container/>"}))
    _write(tmp_path, "plain", b"\x7fELF" + b"\x00" * 100)     # a native binary that is not packed
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "none" and not res.evidence
    assert fake.calls == [] and fake.upx_calls == []
    assert "no .pyc" in res.notes


def test_solve_skips_intakes_own_recon_and_unpacked_folders(fake, tmp_path):
    # recon/ (this and other engines' output) and unpacked/ (the sweep's copy of an archive's members)
    # are not handout files: a jar's classes under unpacked/ would be decompiled a second time.
    fake.responses["pycdc"] = FakeResult(stdout=b"ok = 1\n")
    fake.responses["cfr"] = FakeResult(files={"A.java": b"class A{}"})
    _write(tmp_path, "recon/recover/old/old.pyc", pyc_bytes(b"old" * 8))
    _write(tmp_path, "recon/engines/x/out.pyc", pyc_bytes(b"eng" * 8))
    _write(tmp_path, "unpacked/app.jar/A.class", class_bytes())
    _write(tmp_path, "files/app.jar", jar_bytes())
    _write(tmp_path, "files/recon/kept.pyc", pyc_bytes(b"kept" * 6))   # only the top-level recon/ is intake's
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "none"
    assert sorted((c[0], c[2][0]) for c in fake.calls) == [("cfr", "input.jar"), ("pycdc", "input.pyc")]
    assert "files/recon/kept.pyc" in res.notes and "old.pyc" not in res.notes


def test_solve_recovers_identical_files_once(fake, tmp_path):
    fake.responses["pycdc"] = FakeResult(stdout=b"ok = 1\n")
    _write(tmp_path, "files/app.pyc", pyc_bytes())
    _write(tmp_path, "files/copy/app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert len(fake.calls) == 1
    assert res.status == "none" and "same bytes as a file already recovered: files/copy/app.pyc" in res.notes


def test_solve_upx_candidate_evidence_and_decompile_chain(fake, decomp, tmp_path):
    unpacked = b"\x7fELF" + b"\x00" * 16 + FLAG.encode() + b"\x00"
    fake.upx = (unpacked, "unpacked by upx -d in the sandbox")
    _write(tmp_path, "files/chal", upx_elf_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == (FLAG,)
    assert fake.upx_calls == [(upx_elf_bytes(), sr.UPX_TIMEOUT)]
    unpack = [e for e in res.evidence if e.kind == "unpack"]
    assert len(unpack) == 1 and "upx unpacked chal of files/chal" in unpack[0].detail
    image = tmp_path / unpack[0].path
    assert re.fullmatch(r"recon/recover/files__chal-[0-9a-f]{8}/chal", unpack[0].path)
    assert image.read_bytes() == unpacked
    # the unpacked image -- not the packed stub -- is handed to the native decompiler
    assert len(decomp.calls) == 1
    path, outdir, timeout, cdir = decomp.calls[0]
    assert path == image and cdir == tmp_path and timeout == sr.DECOMPILE_TIMEOUT
    assert outdir.parent == tmp_path / "recon" / "decompile"
    chained = [e for e in res.evidence if e.kind == "decompile"]
    assert [(e.path, "r2ghidra decompiled main" in e.detail) for e in chained] == [("recon/decompile/x/main.c", True)]


def test_solve_upx_flag_in_the_chained_pseudocode(fake, monkeypatch, tmp_path):
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    monkeypatch.setattr(sr, "_DECOMPILE", FakeDecompile(functions={"main": "recon/decompile/x/main.c"},
                                                        pseudocode=f'puts("{FLAG}");'))
    _write(tmp_path, "chal", upx_elf_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == (FLAG,)


def test_solve_upx_clean_unpack_and_decompile_is_none(fake, decomp, tmp_path):
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    _write(tmp_path, "chal", upx_elf_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "none" and "chal (upx by upx)" in res.notes


def test_solve_upx_unsure_when_the_unpacked_image_is_not_decompiled(fake, monkeypatch, tmp_path):
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    monkeypatch.setattr(sr, "_DECOMPILE", FakeDecompile(note="no decompiler for elf: install radare2"))
    _write(tmp_path, "chal", upx_elf_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "the unpacked image was not decompiled (no decompiler for elf: install radare2)" in res.notes
    assert [e.kind for e in res.evidence] == ["unpack"]


def test_solve_pyinstaller_blocked_still_writes_the_extracted_pyc(fake, tmp_path):
    body = CODE + FLAG.encode()
    _write(tmp_path, "files/app", pyi_bytes([("main", "s", body)], pyver=312))
    res = sr.solve(tmp_path, CSCTF)                           # sandbox down for every decompiler
    # the flag constant is found in the extracted .pyc even though no decompiler ran
    assert res.status == "candidate" and res.flags == (FLAG,) and "sandbox down" in res.notes
    assert [e.kind for e in res.evidence] == ["unpack"]
    assert (tmp_path / res.evidence[0].path).read_bytes() == PYC_312 + b"\x00" * 12 + body
    assert res.evidence[0].path.endswith("/main.pyc")


def test_solve_pyinstaller_blocked_without_a_flag(fake, tmp_path):
    _write(tmp_path, "files/app", pyi_bytes([("main", "s", CODE)], pyver=312))
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "blocked" and [e.kind for e in res.evidence] == ["unpack"]


def test_solve_names_an_oversize_file_and_is_not_a_clean_none(fake, monkeypatch, tmp_path):
    monkeypatch.setattr(sr, "MAX_FILE_BYTES", 128)
    _write(tmp_path, "files/huge", upx_elf_bytes(b"\x00" * 200))
    _write(tmp_path, "files/huge.txt", b"text " * 100)        # not a kind this engine reads: no note
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure"
    assert "files/huge: 288 bytes is over the 128 byte cap" in res.notes and "huge.txt" not in res.notes
    assert fake.upx_calls == []


def test_solve_names_an_unreadable_file_and_is_not_a_clean_none(fake, monkeypatch, tmp_path):
    target = _write(tmp_path, "files/app.pyc", pyc_bytes())
    real = Path.read_bytes

    def read_bytes(self):
        if self == target:
            raise PermissionError("denied")
        return real(self)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and "files/app.pyc: could not be read (PermissionError)" in res.notes
    assert fake.calls == []


def test_solve_counts_files_over_the_cap_and_is_not_a_clean_none(fake, monkeypatch, tmp_path):
    monkeypatch.setattr(sr, "MAX_FILES", 2)
    fake.responses["pycdc"] = FakeResult(stdout=b"ok = 1\n")
    for i in range(4):
        _write(tmp_path, f"m{i}.pyc", pyc_bytes(bytes([i]) * 20))
    res = sr.solve(tmp_path, CSCTF)
    assert len(fake.calls) == 2
    assert res.status == "unsure" and "2 more file(s) not examined (over MAX_FILES=2)" in res.notes
    assert "m0.pyc" in res.notes and "m1.pyc" in res.notes


def test_solve_a_refused_tool_is_not_a_clean_none(fake, tmp_path):
    for tool in ("pycdc", "decompyle3", "pycdas"):
        fake.responses[tool] = ValueError(f"{tool} is not a sandbox tool (upx, 7z)")
    _write(tmp_path, "app.pyc", pyc_bytes())
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and "pycdc is not a sandbox tool" in res.notes


def test_solve_output_folders_do_not_collide(fake, tmp_path):
    # a/b.pyc and a__b.pyc flatten to the same name; each still gets a folder of its own.
    fake.responses["pycdc"] = lambda tool, args, inputs: FakeResult(stdout=b"src = " + repr(inputs[0][1][-3:]).encode())
    _write(tmp_path, "a/b.pyc", pyc_bytes(b"\x00" * 17 + b"one"))
    _write(tmp_path, "a__b.pyc", pyc_bytes(b"\x00" * 17 + b"two"))
    res = sr.solve(tmp_path, CSCTF)
    paths = [e.path for e in res.evidence]
    assert len(paths) == 2 and len({Path(p).parent for p in paths}) == 2
    assert sorted((tmp_path / p).read_bytes() for p in paths) == [b"src = b'one'", b"src = b'two'"]


def test_solve_keeps_a_jars_tree_and_never_writes_outside_its_folder(fake, tmp_path):
    files = {"a/A.java": b"class A{}", "b/A.java": b"class A2{}", "../../../evil.java": b"class Evil{}",
             "a__A.java": b"class Flat{}", "x y.java": b"class XSpaceY{}", "x_y.java": b"class XUnderY{}"}
    fake.responses["cfr"] = FakeResult(files=files)
    _write(tmp_path, "app.jar", jar_bytes())
    res = sr.solve(tmp_path, CSCTF)
    got = _outputs(tmp_path)
    folder = got[0].split("/")[0]
    # "x y.java" and "x_y.java" sanitize to one name: the second gets a number, neither is overwritten
    assert got == sorted(f"{folder}/{p}" for p in ("a/A.java", "b/A.java", "evil.java", "a__A.java",
                                                   "x_y.java", "x_y.1.java"))
    base = tmp_path / "recon" / "recover" / folder
    assert {(base / "x_y.java").read_bytes(), (base / "x_y.1.java").read_bytes()} == {b"class XSpaceY{}",
                                                                                      b"class XUnderY{}"}
    assert len(res.evidence) == 6 and not (tmp_path / "evil.java").exists()
    assert not (tmp_path.parent / "evil.java").exists()


def test_solve_holds_to_its_time_budget(fake, tmp_path):
    # Time is the step clock's: each tool call takes all the seconds it was given. Three classes at
    # JVM_TIMEOUT (180 s) each, two tools per class, would be 1080 s; the budget is 100 s.
    clock = StepClock()
    fake.on_run = clock.advance
    fake.responses["cfr"] = FakeResult(code=124)
    fake.responses["vineflower"] = FakeResult(code=124)
    for i in range(3):
        _write(tmp_path, f"C{i}.class", class_bytes(tail=bytes([i]) * 8))
    start = clock()
    res = sr.solve(tmp_path, CSCTF, budget=100.0, clock=clock)
    assert clock() - start <= 100.0                           # no tool was given more than was left
    assert [(c[0], c[3]) for c in fake.calls] == [("cfr", 100.0)]
    assert res.status == "unsure"
    assert "vineflower not run: the time budget is spent" in res.notes
    assert "not examined, the 100 s time budget was spent: C1.class, C2.class" in res.notes


def test_solve_a_file_left_unexamined_by_the_budget_is_not_a_clean_none(fake, tmp_path):
    clock = StepClock()
    fake.on_run = clock.advance
    fake.responses["cfr"] = FakeResult(stdout=b"class C {}\n")     # recovers cleanly, in all the time there is
    for i in range(2):
        _write(tmp_path, f"C{i}.class", class_bytes(tail=bytes([i]) * 8))
    res = sr.solve(tmp_path, CSCTF, budget=100.0, clock=clock)
    assert len(fake.calls) == 1
    assert res.status == "unsure"
    assert "recovered C0.class" in res.notes
    assert "not examined, the 100 s time budget was spent: C1.class" in res.notes


class SlowDecompile(FakeDecompile):
    """decompile_file as its r2 backend spends time at worst: a 30 s `pdg?` probe, then the per-pass
    timeout once for each of its two r2 processes (the numbers are decompile_intake's, checked against
    it in test_chain_limits_match_what_the_native_decompiler_spends). Time is the step clock's."""

    def __init__(self, clock, **kw):
        super().__init__(**kw)
        self.clock = clock

    def __call__(self, path, outdir, *, timeout, challenge_dir):
        self.clock.advance(30.0 + 2 * timeout)
        return super().__call__(path, outdir, timeout=timeout, challenge_dir=challenge_dir)


def test_chain_limits_match_what_the_native_decompiler_spends(monkeypatch, tmp_path):
    # DECOMPILE_PASSES and DECOMPILE_PROBE describe the real decompile_intake r2 backend: it starts r2
    # twice with the timeout it is given, after a plugin probe with a fixed limit. No r2 is run here:
    # the backend's subprocess module is replaced and only the timeouts it asks for are read.
    monkeypatch.setattr(sr, "_DECOMPILE", None)
    module = sr.load_decompiler().__globals__
    asked = []

    class Subprocess:
        DEVNULL = None
        TimeoutExpired = TimeoutError

        @staticmethod
        def run(argv, *, timeout, **_kw):
            asked.append(timeout)
            return type("Done", (), {"stdout": "[]", "stderr": ""})()

    monkeypatch.setitem(module, "subprocess", Subprocess)
    backend = module["R2GhidraBackend"](r2_bin=str(tmp_path / "no-r2"))
    backend.decompile(tmp_path / "image", "elf", b"\x7fELF" + b"\x00" * 16, 7.0)
    assert asked == [7.0] * sr.DECOMPILE_PASSES
    backend._probe_pdg()
    assert asked[-1] == sr.DECOMPILE_PROBE


def test_solve_budget_holds_the_whole_decompile_chain(fake, monkeypatch, tmp_path):
    # decompile_file's timeout is per pass: the chain takes probe + 2 passes. With 110 s left after
    # upx, a pass gets (110 - 30) / 2 = 40 s, not the 110 s that would run the chain to 250 s.
    clock = StepClock()
    fake.on_run = clock.advance
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    slow = SlowDecompile(clock, functions={"main": "recon/decompile/x/main.c"}, pseudocode="int main;")
    monkeypatch.setattr(sr, "_DECOMPILE", slow)
    _write(tmp_path, "chal", upx_elf_bytes())
    budget = sr.UPX_TIMEOUT + 110.0
    start = clock()
    res = sr.solve(tmp_path, CSCTF, budget=budget, clock=clock)
    assert [c[2] for c in slow.calls] == [40.0] and res.status == "none"
    assert clock() - start <= budget                         # upx + probe + both passes fit the budget


def test_solve_skips_the_decompile_chain_when_the_budget_cannot_hold_it(fake, monkeypatch, tmp_path):
    clock = StepClock()
    fake.on_run = clock.advance
    fake.upx = (b"\x7fELFunpacked", "unpacked")
    slow = SlowDecompile(clock, functions={"main": "recon/decompile/x/main.c"})
    monkeypatch.setattr(sr, "_DECOMPILE", slow)
    short, enough = tmp_path / "short", tmp_path / "enough"
    _write(short, "chal", upx_elf_bytes())
    _write(enough, "chal", upx_elf_bytes())
    fits = sr.UPX_TIMEOUT + sr.DECOMPILE_PROBE + sr.DECOMPILE_PASSES * sr.MIN_TOOL_SECONDS
    # one second short of the probe plus two minimal passes: the chain is not started, and says so
    res = sr.solve(short, CSCTF, budget=fits - 1.0, clock=clock)
    assert slow.calls == [] and res.status == "unsure"
    assert "the unpacked image was not decompiled (time budget spent)" in res.notes
    assert [e.kind for e in res.evidence] == ["unpack"]
    start = clock()
    res = sr.solve(enough, CSCTF, budget=fits, clock=clock)   # exactly enough: each pass gets the minimum
    assert [c[2] for c in slow.calls] == [sr.MIN_TOOL_SECONDS] and res.status == "none"
    assert clock() - start == fits


def test_the_default_limits_fit_one_unpack_and_its_decompile_chain():
    # With the production defaults a fresh run gives a pass its whole DECOMPILE_TIMEOUT, and upx plus
    # the chain still end inside the engine's own budget.
    chain = sr.DECOMPILE_PROBE + sr.DECOMPILE_PASSES * sr.DECOMPILE_TIMEOUT
    assert sr.UPX_TIMEOUT + chain <= sr.OVERALL_BUDGET
    clock = StepClock()
    end = clock() + sr.OVERALL_BUDGET - sr.UPX_TIMEOUT
    assert sr._chain_time(lambda: end - clock()) == sr.DECOMPILE_TIMEOUT


# ================================================================== native stub: in-memory unpack
def _zero_carve_memo():
    sr._CARVED[:] = [None, {}]


def test_sniff_stub_finds_a_compressed_native_image(stream_format):
    name, compress = stream_format
    stub = stub_elf(compress(INNER))
    assert FLAG.encode() not in stub                          # the flag is only in the decoded image
    assert sr.embedded_images(stub) == {f"inner-0x44.{name}": INNER}
    assert sr.sniff(stub) == "stub"


def test_sniff_stub_keeps_a_verified_ap32_payload():
    stub = stub_elf(ap32_bytes(b"A\x60B\x00", b"AB"))
    assert sr.embedded_images(stub) == {"inner-0x44.ap32": b"AB"} and sr.sniff(stub) == "stub"
    broken = bytearray(stub)
    broken[0x44 + 20] ^= 1                                    # the original-CRC field: no longer verified
    assert sr.embedded_images(bytes(broken)) == {} and sr.sniff(bytes(broken)) is None


def test_stub_needs_a_native_inner_image_in_a_native_file():
    text = zlib.compress(b"just a compressed string table, not a program " * 4)
    assert sr.embedded_images(stub_elf(text)) == {} and sr.sniff(stub_elf(text)) is None
    in_data_file = b"DATA" + b"\x00" * 64 + zlib.compress(INNER)
    assert sr.embedded_images(in_data_file) == {} and sr.sniff(in_data_file) is None
    in_fat = fat_macho_bytes() + zlib.compress(INNER)
    assert sr.embedded_images(in_fat) == {f"inner-{len(fat_macho_bytes()):#x}.zlib": INNER}


def test_stub_stream_with_a_bad_checksum_is_not_an_image_and_the_search_goes_on(monkeypatch):
    packer = CountingPacker(sr.load_packer())
    monkeypatch.setattr(sr, "_PACKER", packer)
    # an image that does not compress, so its stream is longer than the test decode reads: the damage
    # at its end (the adler32) is only met by the full decode, which must refuse it and move on
    big = INNER + b"".join(hashlib.sha256(bytes([i])).digest() for i in range(32))
    whole = zlib.compress(big)
    assert len(whole) > 2 * sr.CARVE_PROBE_BYTES
    bad = whole[:-1] + bytes([whole[-1] ^ 1])
    assert sr.embedded_images(stub_elf(bad)) == {} and [c[0] for c in packer.calls] == [0x44]
    good = zlib.compress(INNER)
    both = stub_elf(bad + b"\x00" * 8 + good)
    at = 0x44 + len(bad) + 8
    assert sr.embedded_images(both) == {f"inner-{at:#x}.zlib": INNER}
    assert (0x44, "zlib", sr.CARVE_MAX_OUTPUT) in packer.calls and (at, "zlib", sr.CARVE_MAX_OUTPUT) in packer.calls
    assert sr.embedded_images(stub_elf(whole)) == {"inner-0x44.zlib": big}


def test_stub_search_test_decodes_a_start_before_a_full_decode(monkeypatch):
    # Two-byte zlib headers and "BZh" turn up by chance in code. A start that cannot begin a stream
    # is dropped on a short test decode, so only the real stream costs a full decode.
    packer = CountingPacker(sr.load_packer())
    monkeypatch.setattr(sr, "_PACKER", packer)
    noise = ((b"\x78\x9c" + b"\xff" * 30) * 50 + b"BZh9 is not bzip2 " + b"BZhX1AY&SY"
             + (b"\x78\xda" + b"\xff" * 6) * 9 + (b"\x1f\x8b\x08" + b"\xff" * 20) * 3)
    stub = stub_elf(noise + zlib.compress(INNER))
    assert sr.embedded_images(stub) == {f"inner-{0x44 + len(noise):#x}.zlib": INNER}
    assert packer.calls == [(0x44 + len(noise), "zlib", sr.CARVE_MAX_OUTPUT)]


def test_stub_search_stops_after_the_decode_cap(monkeypatch):
    packer = CountingPacker(sr.load_packer())
    monkeypatch.setattr(sr, "_PACKER", packer)
    texts = [zlib.compress(f"string table {i} ".encode() * 6) for i in range(2)]
    stub = stub_elf(texts[0] + texts[1] + zlib.compress(INNER))
    monkeypatch.setattr(sr, "MAX_CARVE_TRIES", 2)
    assert sr.embedded_images(stub) == {} and len(packer.calls) == 2
    _zero_carve_memo()
    monkeypatch.setattr(sr, "MAX_CARVE_TRIES", 3)
    assert list(sr.embedded_images(stub).values()) == [INNER] and len(packer.calls) == 5


def test_stub_is_decoded_once_for_sniff_and_recover(monkeypatch):
    packer = CountingPacker(sr.load_packer())
    monkeypatch.setattr(sr, "_PACKER", packer)
    stub = stub_elf(zlib.compress(INNER))
    assert sr.sniff(stub) == "stub"
    rec = sr.recover(stub, name="loader")
    assert rec.kind == "stub" and rec.ok and not rec.partial and rec.tool == "packer_unpack"
    assert rec.outputs == {"inner-0x44.zlib": INNER}
    assert len(packer.calls) == 1
    other = stub_elf(zlib.compress(INNER), pad=65)            # other bytes: searched afresh
    assert sr.embedded_images(other) == {"inner-0x45.zlib": INNER} and len(packer.calls) == 2
    got = sr.embedded_images(other)
    got.clear()                                               # the caller's copy, not the kept answer
    assert sr.embedded_images(other) == {"inner-0x45.zlib": INNER} and len(packer.calls) == 2


def test_recover_stub_without_an_inner_image_is_a_named_failure():
    rec = sr.recover(b"\x7fELF" + b"\x00" * 80, name="plain", kind="stub")
    assert rec.kind == "stub" and not rec.ok and not rec.blocked and rec.outputs == {}
    assert "no compressed native image or AP32 payload decodes inside plain" in rec.note


def test_stub_limits_stay_inside_the_decoders_own_caps():
    pu = sr.load_packer()
    assert sr.CARVE_MAX_BYTES <= pu.MAX_INPUT and sr.CARVE_MAX_OUTPUT <= pu.MAX_OUTPUT


def test_solve_stub_is_unpacked_in_memory_and_chained_to_the_decompiler(fake, decomp, tmp_path):
    _write(tmp_path, "files/loader", stub_elf(zlib.compress(INNER)))
    res = sr.solve(tmp_path, CSCTF)                           # the sandbox is down: it is not needed
    assert res.status == "candidate" and res.flags == (FLAG,)
    assert fake.calls == [] and fake.upx_calls == []
    unpack = [e for e in res.evidence if e.kind == "unpack"]
    assert len(unpack) == 1
    assert unpack[0].detail == "packer_unpack unpacked inner-0x44.zlib of files/loader"
    assert re.fullmatch(r"recon/recover/files__loader-[0-9a-f]{8}/inner-0x44\.zlib", unpack[0].path)
    image = tmp_path / unpack[0].path
    assert image.read_bytes() == INNER
    assert [(c[0], c[2], c[3]) for c in decomp.calls] == [(image, sr.DECOMPILE_TIMEOUT, tmp_path)]
    assert decomp.calls[0][1].parent == tmp_path / "recon" / "decompile"
    assert [e.path for e in res.evidence if e.kind == "decompile"] == ["recon/decompile/x/main.c"]


def test_solve_stub_payload_that_is_not_an_executable_is_kept_but_not_decompiled(fake, decomp, tmp_path):
    _write(tmp_path, "files/loader", stub_elf(ap32_bytes(b"A\x60B\x00", b"AB")))
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "none" and "files/loader (stub by packer_unpack)" in res.notes
    assert decomp.calls == [] and [e.kind for e in res.evidence] == ["unpack"]
    assert (tmp_path / res.evidence[0].path).read_bytes() == b"AB"


def test_solve_names_a_native_file_too_large_for_the_inner_image_search(fake, monkeypatch, tmp_path):
    stub = stub_elf(zlib.compress(INNER))
    monkeypatch.setattr(sr, "CARVE_MAX_BYTES", len(stub) - 1)
    assert sr.embedded_images(stub) == {} and sr.sniff(stub) is None
    _write(tmp_path, "files/big", stub)
    _write(tmp_path, "files/small", b"\x7fELF" + b"\x00" * (len(stub) - 5))   # native, exactly at the cap
    _write(tmp_path, "files/big.zip", plain_zip_bytes() + b"\x00" * len(stub))   # not native: not named
    res = sr.solve(tmp_path, CSCTF)
    assert res.status == "none" and not res.evidence
    assert res.notes.endswith(f"not searched for a compressed inner image (over the {len(stub) - 1} byte cap): "
                              "files/big")
    monkeypatch.setattr(sr, "CARVE_MAX_BYTES", len(stub))     # exactly at the cap: searched
    assert sr.sniff(stub) == "stub"


# ================================================================== wiring
def _real_sandbox():
    spec = importlib.util.spec_from_file_location("sandbox_wiring_check", sr.SANDBOX_CLIENT)
    sb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sb)
    return sb


def test_sandbox_tools_list_holds_the_new_decompilers():
    # The TOOLS edit routes pycdc/pycdas/decompyle3/cfr/vineflower to csctf-sandbox:2 (gen 2). Without
    # it sandbox.run raises ValueError('not a sandbox tool') and the adapters could never dispatch.
    sb = _real_sandbox()
    for tool in ("pycdc", "pycdas", "decompyle3", "cfr", "vineflower"):
        assert tool in sb.TOOLS
        assert [g.n for g in sb.gens(tool)] == [2]           # only the :2 image holds them


def test_real_upx_unpack_passes_start_to_run(monkeypatch):
    sb = _real_sandbox()
    seen = []

    def run(tool, args=(), inputs=(), timeout=0.0, **kw):
        seen.append((tool, timeout, kw.get("start")))
        raise sb.SandboxDown("not started")
    monkeypatch.setattr(sb, "run", run)
    assert sb.upx_unpack(b"x", 3.0, start=False) == (None, "sandbox down: not started: the packed image is not read")
    sb.upx_unpack(b"x", 4.0)
    assert seen == [("upx", 3.0, False), ("upx", 4.0, True)]


def test_manifest_loads_and_wires_the_intake_adapter():
    from ctf.engines import manifest
    m = manifest.load(Path(sr.__file__).with_name("sandbox_recover.manifest.toml"))
    assert m.id == "binary.sandbox_recover"
    assert m.entry.target_file(ROOT).resolve() == Path(sr.__file__).resolve()
    assert m.intake is not None and m.intake.run == "challenge" and m.intake.select == "files"
    assert m.intake.spawns is True
    # the engine's own deadline ends before intake's kill, with room for one docker call's slack
    assert sr.OVERALL_BUDGET + 30 <= m.intake.timeout


def test_collaborators_load_from_the_sibling_files(monkeypatch):
    monkeypatch.setattr(sr, "_DECOMPILE", None)
    monkeypatch.setattr(sr, "_PYI", None)
    fn = sr.load_decompiler()
    assert fn.__name__ == "decompile_file" and Path(fn.__code__.co_filename).name == "decompile_intake.py"
    pyi = sr.load_pyinstaller()
    assert pyi.MAGIC == sr._PYI_COOKIE and callable(pyi.extract_carchive)
    monkeypatch.setattr(sr, "_PACKER", None)
    pu = sr.load_packer()
    assert Path(pu.__file__).name == "packer_unpack.py" and Path(pu.__file__).parent == Path(sr.__file__).parent
    assert pu.decompress_carved(zlib.compress(b"abc"), pu.CarvedStream(0, "zlib", 0, "t")).data == b"abc"
    assert sr.load_packer() is pu                             # loaded once


def test_dockerfile_pins_every_b167_download_and_takes_no_build_arg():
    # `tools/sandbox.py build`, setup.sh and docker/README.md all run `docker build` with no
    # --build-arg, so an ARG without a default that a download asserts on makes :2 unbuildable.
    text = (ROOT / "docker" / "sandbox" / "Dockerfile.2").read_text(encoding="utf-8")
    assert re.findall(r"^ARG\s+\w+\s*$", text, re.M) == []
    assert "--build-arg" not in text and "os.environ" not in text
    commit = re.search(r'commit = "([0-9a-f]{40})"', text)
    assert commit and f"/src/pycdc-{commit.group(1)}" in text
    for needle in ("zrax/pycdc/archive/{commit}.tar.gz", "cfr/releases/download/", "vineflower/releases/download/"):
        at = text.index(needle)
        assert re.search(r'"[0-9a-f]{64}"', text[at:at + 400]), f"no sha256 pin next to {needle}"
    # decompyle3 has no __main__: the wrapper calls its console entry; the smoke line fails closed.
    assert "-m decompyle3" not in text and "from decompyle3.bin.decompile import main_bin" in text
    assert "RUN pycdc --help && pycdas --help && decompyle3 --version && java" in text
