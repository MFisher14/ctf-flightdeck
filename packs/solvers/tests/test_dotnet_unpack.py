"""B-054: .NET single-file bundle / NODE_SEA unpack + decompile at intake.

These tests build their fixtures by hand -- a .NET single-file bundle is a native apphost with a
manifest (the ``BUNDLE_SIG`` placeholder, a header offset, then the file table) and its member bodies
appended; a NODE_SEA blob is the ``SEA_MAGIC`` marker, flags, then length-prefixed strings -- so no
real challenge file is committed and no tool is needed for the unpack itself. The one test that needs
a real sample (csctf 9085-poshterm) is marked ``needs_realdata`` and reports NOT RUN without the
corpus. Tests that would otherwise depend on whether radare2 / ilspycmd happen to be installed on the
build host force the tool state with monkeypatch, so they are deterministic everywhere.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "binary"))

import decompile_intake as di          # noqa: E402  (flat import, the engine sys.path)
from ctf import event, paths           # noqa: E402

CSCTF = event.load("csctf")


# ------------------------------------------------------------------ fixture builders
def _bwstr(s: str) -> bytes:
    """A .NET ``BinaryWriter`` 7-bit-encoded-length string (what the bundle manifest uses)."""
    b = s.encode("utf-8")
    n = len(b)
    out = bytearray()
    while True:
        x = n & 0x7F
        n >>= 7
        if n:
            out.append(x | 0x80)
        else:
            out.append(x)
            break
    return bytes(out) + b


def build_bundle(members, *, major=6, minor=0):
    """A synthetic .NET single-file bundle. ``members`` is ``[(path, type_code, body)]``
    (type 1 = assembly, 3 = deps_json, ...). Stored uncompressed (packed=0)."""
    blob = bytearray(b"MZ" + b"\x00" * 62)        # a PE-ish apphost head
    placed = []
    for path, tc, body in members:
        off = len(blob)
        blob += body
        placed.append((path, tc, off, len(body)))
    sig_hdr_pos = len(blob)
    blob += b"\x00" * 8                            # the 8-byte header-offset placeholder before the sig
    blob += di._runtime_facts().BUNDLE_SIG
    hdr_off = len(blob)
    man = bytearray()
    man += struct.pack("<IIi", major, minor, len(placed))
    man += _bwstr("bundle-id-abc")
    if major >= 2:
        man += b"\x00" * 40                        # deps/runtimeconfig offsets+sizes, flags
    for path, tc, off, size in placed:
        man += struct.pack("<qq", off, size)
        if major >= 6:
            man += struct.pack("<q", 0)            # packed = 0 (stored)
        man += bytes([tc])
        man += _bwstr(path)
    blob += man
    struct.pack_into("<q", blob, sig_hdr_pos, hdr_off)
    return bytes(blob)


def _fake_assembly(tag: bytes = b"") -> bytes:
    """Bytes that :func:`is_dotnet` accepts: a PE head and a CLI metadata root (``BSJB``)."""
    return b"MZ" + b"\x00" * 60 + b"BSJB\x00\x00\x01\x00" + tag + b"\x00" * 8


def build_sea(path: str, code: str, *, flags: int = 0, pad: bool = True) -> bytes:
    """A synthetic NODE_SEA blob (Node 22 layout: one pad byte, then [u64 len][path][u64 len][code])."""
    blob = bytearray(di.SEA_MAGIC) + struct.pack("<I", flags)
    if pad:
        blob += b"\x00"
    pb = path.encode("utf-8")
    blob += struct.pack("<Q", len(pb)) + pb
    cb = code.encode("utf-8")
    blob += struct.pack("<Q", len(cb)) + cb
    return bytes(blob)


# ------------------------------------------------------------------ bundle_members
def test_bundle_members_extracts_the_apps_own_assembly():
    asm = _fake_assembly()
    data = build_bundle([("App.dll", 1, asm), ("App.deps.json", 3, b'{"k":1}')])
    got = dict(di.bundle_members(data))
    assert "App.dll" in got
    assert got["App.dll"] == asm


def test_bundle_members_empty_for_a_file_without_the_signature():
    # a native file with no bundle signature anywhere
    assert di.bundle_members(b"MZ" + b"\x00" * 500) == []


def test_bundle_members_empty_when_the_manifest_does_not_parse():
    # signature present but the header offset points at nothing valid (B-054 relies on
    # facts.dotnet_bundle returning None, so no members are claimed)
    junk = b"MZ" + b"\x00" * 16 + di._runtime_facts().BUNDLE_SIG + b"\x00" * 16
    assert di.bundle_members(junk) == []


# ------------------------------------------------------------------ sea_members
def test_sea_members_reads_the_main_script():
    data = build_sea("main.js", "console.log('hi');\n")
    got = dict(di.sea_members(data))
    assert "main.js" in got
    assert b"console.log" in got["main.js"]


def test_sea_members_finds_a_blob_injected_into_a_native_host():
    inner = build_sea("app.js", "const x = 1;\n")
    host = b"\x7fELF" + b"\x00" * 128 + inner + b"\x00" * 64     # postject-style injection
    got = dict(di.sea_members(host))
    assert "app.js" in got and b"const x" in got["app.js"]


def test_sea_members_empty_without_the_magic():
    assert di.sea_members(b"\x7fELF" + b"\x00" * 200) == []


# ------------------------------------------------------------------ _safe_member (no traversal)
def test_safe_member_strips_traversal_and_absolute_parts():
    assert di._safe_member("../../etc/passwd") == "etc/passwd"
    assert di._safe_member("/abs/App.dll") == "abs/App.dll"
    assert di._safe_member("..") == "member"
    assert ".." not in di._safe_member("a/../../b")


def test_unpack_file_never_writes_outside_its_output_folder(tmp_path):
    asm = _fake_assembly()
    data = build_bundle([("../../escape.dll", 1, asm)])
    f = tmp_path / "apphost"
    f.write_bytes(data)
    out_root = tmp_path / "recon" / "unpack"
    u = di.unpack_file(f, out_root, challenge_dir=tmp_path)
    for wrote in u.members.values():
        target = (tmp_path / wrote).resolve()
        assert out_root.resolve() in target.parents     # stayed inside the unpack folder
    assert not (tmp_path.parent / "escape.dll").exists()


# ------------------------------------------------------------------ unpack_file
def test_unpack_file_writes_bundle_members_and_queues_assemblies(tmp_path):
    asm = _fake_assembly()
    data = build_bundle([("App.dll", 1, asm)])
    f = tmp_path / "files" / "apphost"
    f.parent.mkdir()
    f.write_bytes(data)
    out_root = tmp_path / "recon" / "unpack"
    u = di.unpack_file(f, out_root, challenge_dir=tmp_path)
    assert u.kind == "dotnet_bundle"
    assert "App.dll" in u.members
    written = tmp_path / u.members["App.dll"]
    assert written.is_file() and written.read_bytes() == asm
    assert u.assemblies == [written]                      # the .NET assembly is queued for decompile


def test_unpack_file_does_not_queue_a_non_dotnet_dll_member(tmp_path):
    # A bundle member named *.dll whose body is not a CLI/.NET image (no BSJB metadata root): the
    # manifest marks it an app assembly so it is extracted, but is_dotnet(body) is False, so the
    # is_dotnet guard at unpack_file keeps it off the .NET-decompile queue (decompile_file still
    # handles it as a native file). Without that guard this native .dll would be mis-queued.
    native = b"MZ" + b"\x00" * 200                        # PE-ish, but carries no BSJB -> not .NET
    assert not di.is_dotnet(native)
    data = build_bundle([("Native.dll", 1, native)])
    f = tmp_path / "files" / "apphost"
    f.parent.mkdir()
    f.write_bytes(data)
    out_root = tmp_path / "recon" / "unpack"
    u = di.unpack_file(f, out_root, challenge_dir=tmp_path)
    assert u.kind == "dotnet_bundle"
    assert "Native.dll" in u.members                      # the member is still extracted to disk
    written = tmp_path / u.members["Native.dll"]
    assert written.is_file() and written.read_bytes() == native
    assert written not in u.assemblies                    # but not queued as a .NET assembly
    assert u.assemblies == []


def test_unpack_file_writes_the_sea_script(tmp_path):
    data = build_sea("main.js", "const flag = 'x';\n")
    f = tmp_path / "app.blob"
    f.write_bytes(data)
    out_root = tmp_path / "recon" / "unpack"
    u = di.unpack_file(f, out_root, challenge_dir=tmp_path)
    assert u.kind == "node_sea"
    written = tmp_path / u.members["main.js"]
    assert written.is_file() and b"const flag" in written.read_bytes()
    assert u.assemblies == []                             # a SEA script is source, not an assembly


def test_unpack_file_ignores_a_plain_native_binary(tmp_path):
    f = tmp_path / "prog"
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128)
    u = di.unpack_file(f, tmp_path / "o", challenge_dir=tmp_path)
    assert u.kind is None and not u.members


# ------------------------------------------------------------------ solve end to end
def test_solve_finds_a_flag_in_an_unpacked_sea_script(tmp_path):
    # No tool needed: the flag is in the SEA main script's source text.
    files = tmp_path / "files"
    files.mkdir()
    (files / "app.blob").write_bytes(build_sea("main.js", "const f='csctf{sea_unpacked}';\n"))
    res = di.solve(tmp_path, CSCTF)
    assert res.status == "candidate"
    assert "csctf{sea_unpacked}" in res.flags
    assert any(e.kind == "unpack" and e.path.endswith("main.js") for e in res.evidence)


def test_solve_finds_a_flag_in_an_extracted_bundle_member(tmp_path):
    # The flag sits in the app's own assembly bytes (preceded by a NUL so it is at a word boundary);
    # the member-text scan picks it up without decompiling.
    asm = _fake_assembly(b"\x00csctf{in_the_assembly}\x00")
    files = tmp_path / "files"
    files.mkdir()
    (files / "apphost").write_bytes(build_bundle([("App.dll", 1, asm)]))
    res = di.solve(tmp_path, CSCTF)
    assert res.status == "candidate"
    assert "csctf{in_the_assembly}" in res.flags


def test_solve_blocks_naming_ilspycmd_when_no_decompiler_is_installed(tmp_path, monkeypatch):
    # Force "no tool installed" regardless of the build host: _resolve finds nothing, so neither a
    # native decompiler nor ilspycmd is available. The bundle is still unpacked, and the extracted
    # assembly's decompile fails loudly naming the ilspycmd install (a human step).
    monkeypatch.setattr(di, "_resolve", lambda *names: None)
    di._r2_pdg_cache.clear()
    files = tmp_path / "files"
    files.mkdir()
    (files / "apphost").write_bytes(build_bundle([("App.dll", 1, _fake_assembly())]))
    res = di.solve(tmp_path, CSCTF)
    assert res.status == "blocked"
    assert "ilspycmd" in res.notes and "dotnet tool install -g ilspycmd" in res.notes
    assert res.flags == ()
    # The blocked result must come from the *extracted assembly* failing to decompile, not only the
    # raw bundle container (the apphost self-classifies as .NET because the appended member carries
    # BSJB, so B-011's native loop already fails on it). Pin the extracted member's own decompile
    # failure: its note names its path under recon/unpack/. Dropping the extracted-assembly decompile
    # loop (u.assemblies[:0]) removes this note and the assertion fails.
    assert "recon/unpack" in res.notes
    # the member was still written out even though nothing could decompile it
    assert list((tmp_path / "recon" / "unpack").rglob("App.dll"))


def test_solve_unpacks_then_decompiles_the_extracted_assembly(tmp_path, monkeypatch):
    # With a decompiler available (stubbed), an extracted assembly is decompiled into recon/decompile/
    # and a flag in its pseudocode is reported.
    class _Fake:
        name = "fake-ilspy"
        formats = ("dotnet",)

        def available(self):
            return True

        def decompile(self, binary, fmt, data, timeout):
            # Return the flag *only* for the extracted assembly (written under recon/unpack/), not for
            # the raw bundle container: the apphost self-classifies as .NET (BSJB sits in the appended
            # member), so B-011's native loop also hands this stub the whole container. Keying on the
            # unpack path pins that the flag came from decompiling the *extracted member*, so dropping
            # the extracted-assembly decompile loop (u.assemblies[:0]) makes this test fail.
            if "unpack" in str(binary):
                return [("assembly", 'string F(){ return "csctf{decompiled_member}"; }')]
            return [("container", "int EntryPoint(){ return 0; }")]   # the raw apphost: no flag

    def _pick(fmt):
        if fmt == "dotnet":
            return _Fake()
        raise di.NoDecompiler("no native decompiler (stubbed off)")
    monkeypatch.setattr(di, "select_backend", _pick)
    files = tmp_path / "files"
    files.mkdir()
    (files / "apphost").write_bytes(build_bundle([("App.dll", 1, _fake_assembly())]))
    res = di.solve(tmp_path, CSCTF)
    assert res.status == "candidate"
    assert "csctf{decompiled_member}" in res.flags
    # the decompile Evidence that carries the flag must be the extracted member's, under recon/unpack/
    assert any(e.kind == "decompile" and "unpack" in e.path for e in res.evidence)


def test_solve_none_when_nothing_to_unpack_or_decompile(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "readme.txt").write_text("nothing here")
    res = di.solve(tmp_path, CSCTF)
    assert res.status == "none"


# ------------------------------------------------------------------ manifest wiring
def test_manifest_declares_unpack_capabilities_and_sea_magic():
    from ctf.engines import manifest as _manifest
    m = _manifest.load(Path(__file__).resolve().parents[1]
                       / "solvers" / "binary" / "decompile_intake.manifest.toml")
    assert {"unpack", "node_sea", "dotnet_bundle"} <= set(m.capabilities)
    assert "magic:0x20da4301" in m.intake.match       # a standalone NODE_SEA blob selects the engine


# ------------------------------------------------------------------ real sample (NOT RUN without corpus)
@pytest.mark.needs_realdata("csctf-9085-poshterm")
def test_poshterm_bundle_is_unpacked(tmp_path):
    """csctf 9085-poshterm is a .NET single-file bundle. Point CTF_REALDATA at a corpus holding
    ``csctf-9085-poshterm/<apphost>`` to exercise the real unpack; absent, this is reported NOT RUN."""
    root = paths.require_realdata() / "csctf-9085-poshterm"
    binaries = [p for p in root.iterdir() if p.is_file()]
    assert binaries, "no sample file under the poshterm corpus"
    u = None
    for b in binaries:
        got = di.unpack_file(b, tmp_path / "unpack", challenge_dir=root)
        if got.kind:
            u = got
            break
    assert u is not None and u.kind == "dotnet_bundle"
    assert u.members
