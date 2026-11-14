"""B-242: the runtime adapter engine (solvers/binary/runtime_trace.py).

The sandbox is a scripted stand-in injected in place of tools/sandbox.py: it records what the engine
asks to run and answers with trace lines written here. The policy gate, the scan, the plans, the
image manifest (tools/images.toml) and the trace parser are real. Fixtures are magic numbers and
zips built by hand: nothing delivered, nothing run, no docker, no network. One test at the end goes
through the real tools/sandbox.py with a docker stand-in that runs the real entry script and runner
on a WebAssembly module written in the test.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

import runtime_trace as rt
from ctf import event, eventpolicy
from ctf.engines import manifest
from ctf.toolchain import images

P = rt.load_plans()
REPO = Path(__file__).resolve().parents[1]
FLAG = "RT{found_at_run_time}"
WASM = b"\x00asm\x01\x00\x00\x00"
BY_NAME = {im.name: im for im in images.load()}


def profile(execution: str | None = "allowed", prefixes=("RT",)) -> event.EventProfile:
    rules = {"submit_mode": "confirm", "flag_sharing": "allowed", "ai_on_platform": "allowed"}
    if execution is not None:
        rules["sandboxed_execution"] = execution
    return event.parse({"slug": "rt-test", "name": "runtime test",
                        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
                        "platform": {"kind": "ctfd", "base_url": "https://board.rt.test"},
                        "flag": {"prefixes": list(prefixes)}, "rules": rules}, src="test")


def doc(runtime="wasm", **over) -> dict:
    d = {"schema": 1, "runtime": runtime, "runtime_version": "test-1", "status": "ok",
         "fuel": {"kind": P.FUEL_KIND[runtime], "limit": 1000, "used": 10, "exhausted": False},
         "entries": [{"name": "check", "signature": "(i32) -> (i32)"}],
         "events": [{"kind": "call", "name": "check", "args": "zeros", "result": "0"}],
         "strings": ["hello"], "notes": [], "truncated": False}
    d.update(over)
    return d


def line(d: dict) -> bytes:
    return P.TRACE_MARKER.encode() + json.dumps(d).encode() + b"\n"


class Res:
    def __init__(self, stdout=b"", code=0, stderr=b""):
        self.stdout, self.code, self.stderr = stdout, code, stderr


class FakeSandbox:
    """Stands in for tools/sandbox.py: `answers` maps an image tag to a Res, an exception to raise,
    or a callable(call) giving either; any other tag answers with an ok trace of its runtime."""

    class SandboxDown(RuntimeError):
        pass

    def __init__(self):
        self.calls, self.answers = [], {}

    def runtime_run(self, tag, want_hash, argv, members, seconds, *, memory, cpus, pids, build_hint=""):
        call = dict(tag=tag, want_hash=want_hash, argv=tuple(argv), members=list(members), seconds=seconds,
                    memory=memory, cpus=cpus, pids=pids, build_hint=build_hint)
        self.calls.append(call)
        answer = self.answers.get(tag, self.answers.get("*"))
        if callable(answer) and not isinstance(answer, type):
            answer = answer(call)
        if isinstance(answer, BaseException):
            raise answer
        if answer is None:
            runtime = tag.split(":")[0].replace("ctf-runtime-", "")
            answer = Res(line(doc(runtime)))
        return answer

    def not_built(self, call):
        return self.SandboxDown(f"the image {call['tag']} is not built ({call['build_hint']})")


@pytest.fixture
def sandbox(monkeypatch):
    fake = FakeSandbox()
    monkeypatch.setattr(rt, "_SANDBOX", fake)
    return fake


@pytest.fixture
def chal(tmp_path):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    return d


def put(chal: Path, rel: str, data: bytes) -> Path:
    p = chal / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def jar(*names: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(zipfile.ZipInfo(n, date_time=(2026, 1, 1, 0, 0, 0)), b"x")
    return buf.getvalue()


def klass(tag: bytes = b"") -> bytes:
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + tag + bytes(8)


def pyc(word: int = 3413, tag: bytes = b"") -> bytes:
    return word.to_bytes(2, "little") + b"\r\n" + bytes(12) + tag


class StepClock:
    """Time that only moves when the test says so (no wall clock in the budget tests)."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# ================================================================================= policy gate
def test_by_default_nothing_is_run_and_the_result_names_the_policy_key(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    res = rt.solve(chal, profile(execution=None))
    assert res.status == "blocked" and res.flags == () and res.engine == "binary.runtime_trace"
    assert "rules.sandboxed_execution = 'forbidden'" in res.notes
    assert "Found: files/a.wasm (wasm module)" in res.notes
    assert sandbox.calls == []
    assert not (chal / "recon").exists()


def test_an_explicit_forbidden_is_the_same_as_the_default(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    assert rt.solve(chal, profile("forbidden")).status == "blocked"
    assert sandbox.calls == []


def test_the_gate_is_the_one_in_eventpolicy(chal, sandbox, monkeypatch):
    put(chal, "files/a.wasm", WASM)
    monkeypatch.setattr(eventpolicy, "execution_refusal", lambda prof: "the player said not today")
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "blocked" and "not run: the player said not today" in res.notes
    assert sandbox.calls == []


@pytest.mark.parametrize("rel", ["files/a.wasm", "recon/unpack/app.exe/a.wasm", "recon/recover/dist-1/a.wasm"])
@pytest.mark.parametrize("opts", [{}, {"only": "<rel>"}, {"probe": "x"}, {"seconds": 7}, {"fuel": 1234},
                                  {"only": "<rel>", "probe": "x", "seconds": 7, "fuel": 1234}],
                         ids=["none", "only", "probe", "seconds", "fuel", "all"])
@pytest.mark.parametrize("execution", [None, "forbidden"])
def test_the_gate_holds_for_every_option_and_every_place_an_artifact_comes_from(chal, sandbox, rel, opts,
                                                                                execution):
    put(chal, rel, WASM)
    opts = {k: (rel if v == "<rel>" else v) for k, v in opts.items()}
    res = rt.solve(chal, profile(execution), **opts)
    assert res.status == "blocked" and "rules.sandboxed_execution = 'forbidden'" in res.notes
    assert f"Found: {rel} (wasm module)" in res.notes
    assert sandbox.calls == []
    assert not (chal / "recon" / "runtime").exists()


def test_allowed_runs_the_artifact(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "none" and len(sandbox.calls) == 1


def test_with_nothing_to_trace_the_policy_is_not_the_reason(chal, sandbox):
    put(chal, "files/readme.txt", b"just text\n")
    res = rt.solve(chal, profile("forbidden"))
    assert res.status == "none" and "sandboxed_execution" not in res.notes
    assert res.notes.startswith("no WebAssembly module")


# ========================================================================================= scan
def test_the_scan_reads_the_handout_and_what_the_earlier_steps_unpacked(chal):
    put(chal, "files/a.wasm", WASM + b"a")
    put(chal, "root.class", klass(b"r"))
    put(chal, "recon/unpack/app.exe/main", b"console.log(1)\n")
    put(chal, "recon/unpack/app.exe/lib.cjs", b"module.exports = 1\n")
    put(chal, "recon/recover/dist-1234abcd/entry.pyc", pyc(3531))
    put(chal, "recon/engines/other/x.wasm", WASM + b"not ours")
    put(chal, "unpacked/copy.wasm", WASM + b"sweep copy")
    got = [(f.rel, f.target.runtime, f.target.kind, f.origin) for f in rt.scan(chal).found]
    assert got == [
        ("files/a.wasm", "wasm", "module", "handout"),
        ("root.class", "jvm", "class", "handout"),
        ("recon/unpack/app.exe/lib.cjs", "node", "source", "recon/unpack"),
        ("recon/unpack/app.exe/main", "node", "source", "recon/unpack"),
        ("recon/recover/dist-1234abcd/entry.pyc", "python", "pyc", "recon/recover"),
    ]


def test_source_text_in_the_handout_is_not_traced_unless_named(chal):
    put(chal, "files/server.py", b"print(1)\n")
    put(chal, "files/app.js", b"console.log(1)\n")
    put(chal, "files/x.lua", b"print(1)\n")
    assert rt.scan(chal).found == []
    only = rt.scan(chal, "files/server.py")
    assert [(f.rel, f.target.runtime, f.target.variants, f.origin) for f in only.found] == [
        ("files/server.py", "python", ("3.12",), "only")]


def test_source_text_under_recon_recover_is_not_traced(chal):
    put(chal, "recon/recover/app-12345678/Main.java", b"class Main {}\n")
    put(chal, "recon/recover/app-12345678/main.py", b"print(1)\n")
    assert rt.scan(chal).found == []


def test_only_takes_one_regular_file_inside_the_folder(chal, tmp_path):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/b.wasm", WASM + b"b")
    outside = tmp_path / "outside.wasm"
    outside.write_bytes(WASM)
    (chal / "files" / "link.wasm").symlink_to(outside)
    assert [f.rel for f in rt.scan(chal, "files/b.wasm").found] == ["files/b.wasm"]
    for bad in ("../outside.wasm", "files/link.wasm", "files/missing.wasm", "files", str(outside)):
        s = rt.scan(chal, bad)
        assert s.found == [] and s.skipped == [f"{bad}: not a regular file inside the challenge folder"], bad
    s = rt.scan(chal, "files/../files/a.wasm")
    assert [f.path.resolve() for f in s.found] == [(chal / "files" / "a.wasm").resolve()]


def test_only_on_a_file_no_adapter_reads_says_so(chal):
    put(chal, "files/notes.txt", b"text\n")
    put(chal, "files/data.zip", jar("a.txt"))
    for rel in ("files/notes.txt", "files/data.zip"):
        s = rt.scan(chal, rel)
        assert s.found == [] and s.skipped == [f"{rel}: no runtime adapter reads it"]


def test_symlinks_are_never_followed(chal, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "x.wasm").write_bytes(WASM)
    (chal / "files" / "dirlink").symlink_to(real, target_is_directory=True)
    (chal / "files" / "filelink.wasm").symlink_to(real / "x.wasm")
    assert rt.scan(chal).found == []


def test_identical_bytes_are_taken_once(chal):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/b.wasm", WASM)
    s = rt.scan(chal)
    assert [f.rel for f in s.found] == ["files/a.wasm"] and s.duplicates == ["files/b.wasm"]


def test_artifacts_over_the_cap_are_counted(chal, monkeypatch):
    monkeypatch.setattr(rt, "MAX_ARTIFACTS", 2)
    for i in range(4):
        put(chal, f"files/m{i}.wasm", WASM + bytes([i]))
    s = rt.scan(chal)
    assert [f.rel for f in s.found] == ["files/m0.wasm", "files/m1.wasm"] and s.overflow == 2


def cil(tag: bytes = b"") -> bytes:
    """The smallest bytes classify calls a CIL assembly: an MZ header, a PE32 optional header and a
    CLR runtime-header directory entry that is set (nothing that would load)."""
    pe, opt = 0x40, 0x40 + 24
    blob = bytearray(opt + 96 + 16 * 8)
    blob[:2] = b"MZ"
    blob[0x3C:0x40] = pe.to_bytes(4, "little")
    blob[pe:pe + 4] = b"PE\x00\x00"
    blob[opt:opt + 2] = b"\x0b\x01"
    blob[opt + 96 + 14 * 8:opt + 96 + 15 * 8] = struct.pack("<II", 0x2008, 0x48)
    return bytes(blob) + tag


FRAMEWORK = ["Microsoft.CSharp.dll", "Microsoft.Win32.Primitives.dll", "System.Collections.dll",
             "System.Console.dll", "System.Linq.dll", "System.Private.CoreLib.dll", "System.Runtime.dll",
             "System.Text.Encoding.dll", "mscorlib.dll", "netstandard.dll", "System.dll", "WindowsBase.dll",
             "System.Threading.dll", "Microsoft.VisualBasic.dll", "System.IO.dll", "System.Memory.dll"]


@pytest.mark.parametrize("marker", ["crackme.runtimeconfig.json", "crackme.deps.json", None])
def test_a_bundles_own_assembly_is_kept_over_its_framework_assemblies(chal, marker):
    # 16 framework assemblies, the app's own assembly and a plain library: more than MAX_ARTIFACTS (12),
    # and in name order the app's comes after every Microsoft.* one. Without a runtimeconfig / deps.json
    # the bundle folder's name (B-054's recon/unpack/<host>/) names the entry assembly.
    base = "recon/unpack/crackme/" if marker is None else "recon/unpack/bundle.bin/"
    for i, name in enumerate(FRAMEWORK):
        put(chal, base + name, cil(bytes([i])))
    put(chal, base + "crackme.dll", cil(b"app"))
    put(chal, base + "Zlib.Helper.dll", cil(b"lib"))
    if marker:
        put(chal, base + marker, b"{}")
    s = rt.scan(chal)
    got = [f.rel[len(base):] for f in s.found]
    assert len(got) == rt.MAX_ARTIFACTS and s.overflow == len(FRAMEWORK) + 2 - rt.MAX_ARTIFACTS
    assert got[:2] == ["crackme.dll", "Zlib.Helper.dll"]               # traced first
    assert got[2:] == sorted(FRAMEWORK)[:rt.MAX_ARTIFACTS - 2]          # the framework fills the rest, in walk order
    assert sorted(s.dropped) == sorted(base + n for n in FRAMEWORK if n not in got)


def test_the_framework_rank_is_by_name_and_only_for_assemblies(chal):
    for name in ("System.Foo.dll", "Microsoft.Bar.dll", "mscorlib.dll", "netstandard.dll", "WindowsBase.dll",
                 "SYSTEM.dll", "runtime.native.System.dll"):
        assert rt.rank(chal / "files" / name, P.classify(cil(), name), chal) == rt.RANK_FRAMEWORK, name
    for name in ("Systemic.dll", "app.dll", "MicrosoftLike.dll", "crackme.exe"):
        assert rt.rank(chal / "files" / name, P.classify(cil(), name), chal) == rt.RANK_OTHER, name
    assert rt.rank(chal / "files" / "System.Foo.class", P.classify(klass(), "x"), chal) == rt.RANK_OTHER


def test_the_entry_rank_needs_its_own_marker_or_its_own_bundle_folder(chal):
    put(chal, "files/app.dll", cil())
    put(chal, "files/other.runtimeconfig.json", b"{}")
    t = P.classify(cil(), "app.dll")
    assert rt.rank(chal / "files" / "app.dll", t, chal) == rt.RANK_OTHER
    put(chal, "files/App.deps.json", b"{}")
    assert rt.rank(chal / "files" / "App.dll", t, chal) == rt.RANK_ENTRY
    assert rt.rank(chal / "recon" / "unpack" / "app.exe" / "app.dll", t, chal) == rt.RANK_ENTRY
    assert rt.rank(chal / "recon" / "unpack" / "app.exe" / "sub" / "app.dll", t, chal) == rt.RANK_ENTRY
    assert rt.rank(chal / "recon" / "unpack" / "host" / "app.dll", t, chal) == rt.RANK_OTHER
    assert rt.rank(chal / "recon" / "recover" / "app" / "app.dll", t, chal) == rt.RANK_OTHER
    assert rt.rank(chal / "files" / "app" / "app.dll", t, chal) == rt.RANK_OTHER


def test_a_symlinked_marker_does_not_make_an_entry_assembly(chal, tmp_path):
    put(chal, "files/app.dll", cil())
    real = tmp_path / "real.json"
    real.write_bytes(b"{}")
    (chal / "files" / "app.runtimeconfig.json").symlink_to(real)
    assert rt.rank(chal / "files" / "app.dll", P.classify(cil(), "app.dll"), chal) == rt.RANK_OTHER


def test_the_cap_drops_the_latest_of_the_worst_rank_and_names_them(chal, sandbox, monkeypatch):
    monkeypatch.setattr(rt, "MAX_ARTIFACTS", 2)
    put(chal, "files/System.A.dll", cil(b"a"))
    put(chal, "files/m0.wasm", WASM + b"0")
    put(chal, "files/m1.wasm", WASM + b"1")
    put(chal, "files/System.B.dll", cil(b"b"))
    s = rt.scan(chal)
    assert [f.rel for f in s.found] == ["files/m0.wasm", "files/m1.wasm"]
    assert s.dropped == ["files/System.B.dll", "files/System.A.dll"] and s.overflow == 2
    res = rt.solve(chal, profile("allowed"))
    assert "2 more artifact(s) not traced (over MAX_ARTIFACTS=2): files/System.B.dll, files/System.A.dll" in res.notes


def test_the_walk_stops_at_its_file_cap_and_says_so(chal, monkeypatch):
    monkeypatch.setattr(rt, "MAX_WALK", 3)
    for i in range(5):
        put(chal, f"files/m{i}.wasm", WASM + bytes([i]))
    s = rt.scan(chal)
    assert len(s.found) == 3 and s.walk_cut is True


def test_a_file_over_the_size_cap_is_named(chal, monkeypatch):
    monkeypatch.setattr(P, "MAX_ARTIFACT_BYTES", 16)
    put(chal, "files/ok.wasm", WASM + bytes(8))                # exactly 16 bytes
    put(chal, "files/big.wasm", WASM + bytes(9))
    s = rt.scan(chal)
    assert [f.rel for f in s.found] == ["files/ok.wasm"]
    assert s.skipped == ["files/big.wasm: 17 bytes is over the 16 byte cap"]


def test_a_version_no_image_reads_is_named(chal):
    put(chal, "files/old.pyc", pyc(3394))
    put(chal, "files/comp.wasm", b"\x00asm\x0d\x00\x01\x00")
    s = rt.scan(chal)
    assert s.found == []
    assert [u.split(":")[0] for u in s.unsupported] == ["files/comp.wasm", "files/old.pyc"]
    assert "3394" in s.unsupported[1]


def test_il2cpp_and_dart_artifacts_are_named_as_not_covered(chal):
    put(chal, "files/global-metadata.dat", b"\xaf\x1b\xb1\xfa" + struct.pack("<i", 29) + bytes(64))
    put(chal, "files/isolate_snapshot_data", b"\xf5\xf5\xdc\xdc" + bytes(16) + b"0123456789abcdef0123456789abcdef" + b"x")
    put(chal, "files/libapp.so", b"\x7fELF" + bytes(60) + b"\x00_kDartIsolateSnapshotData\x00")
    put(chal, "files/plain.so", b"\x7fELF" + bytes(60) + b"nothing dart here")
    s = rt.scan(chal)
    assert s.found == [] and len(s.uncovered) == 3
    by = {u.split(":")[0]: u for u in s.uncovered}
    assert "IL2CPP global-metadata version 29" in by["files/global-metadata.dat"]
    assert "version hash 0123456789abcdef0123456789abcdef" in by["files/isolate_snapshot_data"]
    assert "Flutter / Dart AOT library" in by["files/libapp.so"]


def test_uncovered_artifacts_alone_are_blocked_never_a_clean_none(chal, sandbox):
    put(chal, "files/global-metadata.dat", b"\xaf\x1b\xb1\xfa" + struct.pack("<i", 31) + bytes(64))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "blocked" and "no runtime adapter for: files/global-metadata.dat" in res.notes
    assert sandbox.calls == []


def test_the_engines_own_limits_and_collaborators():
    assert (rt.MAX_ARTIFACTS, rt.MAX_WALK, rt.MAX_SIBLINGS, rt.MAX_NATIVE_SEARCH, rt.HEAD_BYTES) == (
        12, 4000, 64, 64 << 20, 16)
    assert (rt.OVERALL_BUDGET, rt.MIN_RUN_SECONDS, rt.DEFAULT_PROBES) == (600.0, 5, (b"", b"AAAAAAAA"))
    assert rt.SANDBOX_CLIENT == REPO / "tools" / "sandbox.py" and rt.SANDBOX_CLIENT.is_file()
    assert rt.PLANS == REPO / "solvers" / "binary" / "_runtime_plans.py" and rt.PLANS.is_file()
    assert rt.ENGINE == "binary.runtime_trace" and rt.OUT == Path("recon") / "runtime"


def test_every_handout_folder_is_walked_and_only_intakes_own_top_level_output_is_skipped(chal):
    put(chal, "extra/x.wasm", WASM + b"x")
    put(chal, "files/recon/y.wasm", WASM + b"y")
    put(chal, "files/unpacked/z.wasm", WASM + b"z")
    put(chal, "recon/sweep/w.wasm", WASM + b"w")
    assert [f.rel for f in rt.scan(chal).found] == ["files/recon/y.wasm", "files/unpacked/z.wasm", "extra/x.wasm"]


def test_a_file_that_cannot_be_read_is_named(chal):
    locked = put(chal, "files/locked.wasm", WASM)
    locked.chmod(0)
    try:
        s = rt.scan(chal)
    finally:
        locked.chmod(0o644)
    assert s.found == [] and s.skipped == ["files/locked.wasm: could not be read (PermissionError)"]


def test_uncovered_notes_at_their_length_boundaries(chal):
    put(chal, "files/m8.dat", b"\xaf\x1b\xb1\xfa" + struct.pack("<i", -1))          # exactly 8 bytes
    put(chal, "files/m7.dat", b"\xaf\x1b\xb1\xfa" + bytes(3))
    put(chal, "files/s52", b"\xf5\xf5\xdc\xdc" + bytes(16) + b"a" * 32)             # exactly 52 bytes
    put(chal, "files/s51", b"\xdc\xdc\xf5\xf5" + bytes(16) + b"b" * 31)
    by = {u.split(":")[0]: u for u in rt.scan(chal).uncovered}
    assert sorted(by) == ["files/m8.dat", "files/s51", "files/s52"]
    assert "version -1:" in by["files/m8.dat"]
    assert "version hash " + "a" * 32 + ")" in by["files/s52"] and "version hash ?)" in by["files/s51"]


def test_a_big_native_file_is_not_this_engines_business_unless_it_is_named(chal, monkeypatch):
    monkeypatch.setattr(P, "MAX_ARTIFACT_BYTES", 16)
    monkeypatch.setattr(rt, "MAX_NATIVE_SEARCH", 64)
    put(chal, "files/libapp.so", b"\x7fELF" + bytes(8) + b"_kDartIsolateSnapshotData")   # 37 bytes
    put(chal, "files/huge.so", b"\x7fELF" + bytes(100))
    s = rt.scan(chal)
    assert [u.split(":")[0] for u in s.uncovered] == ["files/libapp.so"] and s.skipped == []
    assert rt.scan(chal, "files/huge.so").skipped == ["files/huge.so: 104 bytes is over the 16 byte cap"]


# ========================================================================================== run
def test_a_flag_in_the_trace_is_a_candidate_with_the_trace_as_evidence(chal, sandbox):
    art = put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = Res(line(doc(strings=["hello", "the key is " + FLAG])))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "candidate" and res.flags == (FLAG,)
    assert "dynamic, unverified" in res.notes
    paths = {e.path for e in res.evidence}
    assert len(paths) == 1
    written = chal / paths.pop()
    assert written.parent.parent == chal / "recon" / "runtime" and written.name == "trace.json"
    record = json.loads(written.read_text())
    assert written.read_text() == json.dumps(record, indent=1, sort_keys=True)
    assert record["artifact"] == "files/a.wasm" and record["origin"] == "handout" and record["kind"] == "module"
    assert record["sha256"] == hashlib.sha256(art.read_bytes()).hexdigest() and record["size"] == len(WASM)
    assert record["image"] == "ctf-runtime-wasm:1" and record["exit_code"] == 0
    assert record["plan"]["network"] == "none" and record["plan"]["mounts"] == []
    assert record["trace"]["strings"] == ["hello", "the key is " + FLAG]
    assert [e.kind for e in res.evidence] == ["trace", "trace"]
    assert res.evidence[0].detail == ("wasm test-1 traced files/a.wasm in ctf-runtime-wasm:1: 1 entry point(s), "
                                      "1 event(s), 2 string(s) observed, status ok")
    assert res.evidence[1].detail == "flag-format string observed at run time in files/a.wasm"


def test_a_flag_in_an_event_field_counts_too(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = Res(line(doc(strings=[], events=[{"kind": "static", "name": "K", "value": FLAG}])))
    assert rt.solve(chal, profile("allowed")).flags == (FLAG,)


def test_the_same_flag_from_two_artifacts_is_reported_once(chal, sandbox):
    put(chal, "files/a.wasm", WASM + b"a")
    put(chal, "files/b.wasm", WASM + b"b")
    sandbox.answers["*"] = Res(line(doc(strings=[FLAG])))
    res = rt.solve(chal, profile("allowed"))
    assert res.flags == (FLAG,) and len(sandbox.calls) == 2


def test_a_complete_trace_without_a_flag_is_none_and_points_at_the_trace(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "none" and res.flags == ()
    assert res.notes == "traced files/a.wasm (wasm module) to recon/runtime/"
    assert len(res.evidence) == 1 and (chal / res.evidence[0].path).is_file()


def test_a_partial_trace_is_unsure_and_says_why(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = Res(line(doc(
        status="partial", truncated=True, notes=["a runner note"],
        fuel={"kind": "instructions", "limit": 1000, "used": 1000, "exhausted": True},
        events=[{"kind": "call", "name": "spin", "args": "zeros", "error": "out of fuel"}])))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure"
    assert ("traced in part: files/a.wasm (wasm module): out of instructions fuel (1000); spin(zeros): out of fuel; "
            "a runner note; the trace was cut at its size caps") in res.notes
    assert len(res.evidence) == 1


def test_a_flag_in_a_partial_trace_is_still_a_candidate(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = Res(line(doc(status="partial", strings=[FLAG])))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "candidate" and "traced in part" in res.notes


def test_an_artifact_the_runtime_does_not_load_is_unsure_with_the_load_error(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = Res(line(doc(status="error", entries=[], strings=[],
                                        events=[{"kind": "error", "name": "load", "text": "malformed section"}])))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure"
    assert "the runtime did not load: files/a.wasm (wasm module): ctf-runtime-wasm:1: load: malformed section" in res.notes
    assert len(res.evidence) == 1                             # the trace of the failed load is kept


@pytest.mark.parametrize("answer, needle", [
    (Res(b"the artifact printed this and no trace\n", 1, b"runner: boom\nsecond line\n"),
     "printed no trace line (exit 1; runner: boom)"),
    (Res(b"", 124), "printed no trace line (exit 124, stopped at the 35 s limit)"),
    (Res(P.TRACE_MARKER.encode() + b"{broken\n"), "the trace line is not JSON (JSONDecodeError) (exit 0)"),
    (Res(line(doc("jvm"))), "written by runtime 'jvm', not 'wasm' (exit 0)"),
    (Res(b"", 2, b"\x1b[31mcolour\x07\n"), "(exit 2; ?[31mcolour?)"),
])
def test_a_run_that_gives_no_valid_trace_is_named_with_its_exit_status(chal, sandbox, answer, needle):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = answer
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure" and res.evidence == ()
    assert res.notes.startswith("nothing was traced. no trace came back for: files/a.wasm (wasm module): "
                                "ctf-runtime-wasm:1: ")
    assert needle in res.notes
    assert not (chal / "recon").exists()


def test_an_image_that_is_not_built_is_blocked_with_the_build_command(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = sandbox.not_built
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "blocked" and res.evidence == ()
    assert ("no container could run for: files/a.wasm (wasm module): the image ctf-runtime-wasm:1 is not built "
            "(python -m ctf toolchain build --apply --only runtime-wasm)") in res.notes


def test_one_blocked_and_one_traced_is_unsure(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/B.class", klass())
    sandbox.answers["ctf-runtime-jvm:25"] = sandbox.not_built
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure"
    assert "traced files/a.wasm (wasm module)" in res.notes and "no container could run for: files/B.class" in res.notes


def test_a_file_left_out_keeps_a_complete_trace_from_being_a_clean_none(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/old.pyc", pyc(3394))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure" and "no image for: files/old.pyc" in res.notes


def test_duplicates_alone_do_not_spoil_a_clean_none(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/copy.wasm", WASM)
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "none" and "same bytes as an artifact already taken: files/copy.wasm" in res.notes


def test_the_trace_folder_is_the_flattened_path_and_a_hash_of_the_exact_path(chal, sandbox):
    rel = "files/sub dir/we$ird.wasm"
    put(chal, rel, WASM)
    res = rt.solve(chal, profile("allowed"))
    want = "files__sub_dir__we_ird.wasm-" + hashlib.sha256(rel.encode()).hexdigest()[:8]
    assert res.evidence[0].path == f"recon/runtime/{want}/trace.json"
    long = rt._folder("a" * 300)
    assert long.startswith("a" * 120 + "-") and len(long) == 129
    assert rt._folder("..").startswith("file-") and rt._folder("a.b-c_d").startswith("a.b-c_d-")


def test_at_most_three_errors_and_two_runner_notes_are_quoted(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    calls = [{"kind": "call", "name": f"f{i}", "args": "", "error": f"e{i}"} for i in range(5)]
    sandbox.answers["*"] = Res(line(doc(status="partial", events=calls, notes=["n0", "n1", "n2"])))
    res = rt.solve(chal, profile("allowed"))
    assert "files/a.wasm (wasm module): f0(): e0; f1(): e1; f2(): e2; n0; n1" in res.notes
    assert "e3" not in res.notes and "n2" not in res.notes
    load = [{"kind": "error", "name": f"l{i}", "text": f"t{i}"} for i in range(5)]
    sandbox.answers["*"] = Res(line(doc(status="error", events=load)))
    res = rt.solve(chal, profile("allowed"))
    assert "ctf-runtime-wasm:1: l0: t0; l1: t1; l2: t2" in res.notes and "t3" not in res.notes


def test_a_trace_that_gives_no_reason_still_gets_one(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    sandbox.answers["*"] = Res(line(doc(status="error", events=[])))
    assert "ctf-runtime-wasm:1: the runtime did not load it" in rt.solve(chal, profile("allowed")).notes
    sandbox.answers["*"] = Res(line(doc(status="partial", events=[])))
    assert "traced in part: files/a.wasm (wasm module): incomplete" in rt.solve(chal, profile("allowed")).notes


@pytest.mark.parametrize("status", ["partial", "error"])
def test_one_complete_trace_beside_an_incomplete_one_is_unsure(chal, sandbox, status):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/B.class", klass())
    sandbox.answers["ctf-runtime-jvm:25"] = Res(line(doc("jvm", status=status)))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure" and "traced files/a.wasm (wasm module)" in res.notes
    assert len(res.evidence) == 2


def test_one_blocked_and_one_without_a_trace_is_unsure_not_blocked(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    put(chal, "files/B.class", klass())
    sandbox.answers["ctf-runtime-wasm:1"] = sandbox.not_built
    sandbox.answers["ctf-runtime-jvm:25"] = Res(b"nothing useful\n", 1)
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure"
    assert "no trace came back for: files/B.class" in res.notes and "no container could run for: files/a.wasm" in res.notes


# ========================================================================== what is asked to run
def test_the_run_names_the_manifest_image_its_content_hash_and_the_plan(chal, sandbox):
    art = put(chal, "files/a.wasm", WASM + b"body")
    rt.solve(chal, profile("allowed"))
    (call,) = sandbox.calls
    image = BY_NAME["runtime-wasm"]
    assert call["tag"] == image.tag == "ctf-runtime-wasm:1"
    assert call["want_hash"] == images.content_hash(image)
    plan = P.build_plan("wasm", "", probes=[b"", b"AAAAAAAA", b"RT{probe}"])
    assert call["argv"] == plan.argv
    assert call["seconds"] == plan.container_seconds == 35
    assert (call["memory"], call["cpus"], call["pids"]) == (plan.memory, plan.cpus, plan.pids)
    assert call["members"] == [("artifact.bin", art.read_bytes())]
    assert call["build_hint"] == "python -m ctf toolchain build --apply --only runtime-wasm"


def test_the_probes_are_the_defaults_the_flag_shape_and_the_callers_own(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    rt.solve(chal, profile("allowed", prefixes=("ACME", "RT")), probe="letmein")
    argv = sandbox.calls[0]["argv"]
    hexes = [argv[i + 1] for i, a in enumerate(argv) if a == "--probe-hex"]
    assert [bytes.fromhex(h) for h in hexes] == [b"", b"AAAAAAAA", b"ACME{probe}", b"letmein"]


def test_an_event_without_a_known_flag_prefix_gets_no_flag_shaped_probe(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    rt.solve(chal, profile("allowed", prefixes=()), probe=123)
    argv = sandbox.calls[0]["argv"]
    assert [bytes.fromhex(argv[i + 1]) for i, a in enumerate(argv) if a == "--probe-hex"] == [b"", b"AAAAAAAA", b"123"]


@pytest.mark.parametrize("rel, data, tag, head", [
    ("files/m.pyc", pyc(3413), "ctf-runtime-python:3.8", ("python3", "-I", "-B")),
    ("files/m.pyc", pyc(3627), "ctf-runtime-python:3.14", ("python3", "-I", "-B")),
    ("files/c.luac", b"\x1bLua\x51" + bytes(8), "ctf-runtime-lua:1", ("lua5.1", "/opt/runner/trace_runner.lua")),
    ("files/c.luac", b"\x1bLJ\x02" + bytes(8), "ctf-runtime-lua:1", ("luajit", "/opt/runner/trace_runner.lua")),
    ("files/A.class", klass(), "ctf-runtime-jvm:25", ("java",)),
    ("files/app.jar", jar("A.class"), "ctf-runtime-jvm:25", ("java",)),
])
def test_each_kind_goes_to_the_image_and_interpreter_of_its_version(chal, sandbox, rel, data, tag, head):
    put(chal, rel, data)
    res = rt.solve(chal, profile("allowed"))
    (call,) = sandbox.calls
    assert call["tag"] == tag and call["argv"][:len(head)] == head
    assert res.status == "none"


def test_a_jvm_artifact_takes_its_sibling_classes_and_jars_as_dependencies(chal, sandbox, tmp_path):
    put(chal, "files/app/Main.class", klass(b"main"))
    put(chal, "files/app/Helper.class", klass(b"helper"))
    put(chal, "files/app/lib.jar", jar("L.class"))
    put(chal, "files/app/notes.txt", b"not a dependency\n")
    put(chal, "files/app/mod.wasm", WASM)
    put(chal, "files/app/sub/Deep.class", klass(b"deep"))
    outside = tmp_path / "Outside.class"                 # a class outside the challenge folder
    outside.write_bytes(klass(b"outside"))
    (chal / "files" / "app" / "Linked.class").symlink_to(outside)
    rt.solve(chal, profile("allowed"), only="files/app/Main.class")
    (call,) = sandbox.calls
    assert [n for n, _ in call["members"]] == ["artifact.bin", "dep/000.bin", "dep/001.bin"]
    assert call["members"][0][1] == klass(b"main")
    assert call["members"][1][1] == klass(b"helper") and call["members"][2][1] == jar("L.class")


def test_a_wasm_artifact_takes_no_dependencies(chal, sandbox):
    put(chal, "files/a.wasm", WASM + b"a")
    put(chal, "files/b.wasm", WASM + b"b")
    rt.solve(chal, profile("allowed"), only="files/a.wasm")
    assert [n for n, _ in sandbox.calls[0]["members"]] == ["artifact.bin"]


def test_dependencies_stop_at_the_request_caps(chal, sandbox, monkeypatch):
    monkeypatch.setattr(P, "MAX_DEPS", 2)
    put(chal, "files/Main.class", klass(b"main"))
    for i in range(4):
        put(chal, f"files/D{i}.class", klass(bytes([i])))
    rt.solve(chal, profile("allowed"), only="files/Main.class")
    assert [n for n, _ in sandbox.calls[0]["members"]] == ["artifact.bin", "dep/000.bin", "dep/001.bin"]


def test_dependencies_respect_the_size_caps_at_their_boundaries(chal, sandbox, monkeypatch):
    put(chal, "files/Main.class", klass())                    # 16 bytes
    put(chal, "files/A.class", klass(b"a"))                   # 17
    put(chal, "files/B.class", klass(b"bb"))                  # 18
    put(chal, "files/C.class", klass(b"ccc"))                 # 19: over the per-file cap below
    monkeypatch.setattr(P, "MAX_ARTIFACT_BYTES", 18)
    monkeypatch.setattr(P, "MAX_REQUEST_BYTES", 16 + 17 + 18)
    rt.solve(chal, profile("allowed"), only="files/Main.class")
    assert [b for _, b in sandbox.calls[-1]["members"]] == [klass(), klass(b"a"), klass(b"bb")]
    monkeypatch.setattr(P, "MAX_REQUEST_BYTES", 16 + 17 + 17)
    rt.solve(chal, profile("allowed"), only="files/Main.class")
    assert [b for _, b in sandbox.calls[-1]["members"]] == [klass(), klass(b"a")]
    monkeypatch.setattr(P, "MAX_REQUEST_BYTES", 1 << 20)      # room for all: only the per-file cap holds C back
    rt.solve(chal, profile("allowed"), only="files/Main.class")
    assert [b for _, b in sandbox.calls[-1]["members"]] == [klass(), klass(b"a"), klass(b"bb")]


def test_an_unreadable_sibling_is_left_out_not_an_error(chal, sandbox):
    put(chal, "files/Main.class", klass())
    locked = put(chal, "files/Helper.class", klass(b"h"))
    locked.chmod(0)
    try:
        res = rt.solve(chal, profile("allowed"), only="files/Main.class")
    finally:
        locked.chmod(0o644)
    assert res.status == "none" and [n for n, _ in sandbox.calls[0]["members"]] == ["artifact.bin"]


def test_v8_cached_data_is_tried_on_each_node_line_until_one_accepts_it(chal, sandbox):
    put(chal, "files/app.jsc", struct.pack("<I", 0xC0DE0001) + bytes(20))
    rejected = Res(line(doc("node", status="error", entries=[], strings=[],
                            events=[{"kind": "error", "name": "load", "text": "V8 rejected the cached data"}])))
    sandbox.answers["ctf-runtime-node:24"] = rejected
    sandbox.answers["ctf-runtime-node:22"] = Res(line(doc("node", strings=[FLAG])))
    res = rt.solve(chal, profile("allowed"))
    assert [c["tag"] for c in sandbox.calls] == ["ctf-runtime-node:24", "ctf-runtime-node:22"]
    assert res.status == "candidate"
    record = json.loads((chal / res.evidence[0].path).read_text())
    assert record["image"] == "ctf-runtime-node:22" and record["plan"]["variant"] == "22"


def test_v8_cached_data_no_node_line_accepts_names_every_image_tried(chal, sandbox):
    put(chal, "files/app.jsc", struct.pack("<I", 0xC0DE0001) + bytes(20))
    sandbox.answers["*"] = Res(line(doc("node", status="error", entries=[], strings=[],
                                        events=[{"kind": "error", "name": "load", "text": "V8 rejected it"}])))
    res = rt.solve(chal, profile("allowed"))
    assert [c["tag"] for c in sandbox.calls] == ["ctf-runtime-node:24", "ctf-runtime-node:22", "ctf-runtime-node:20"]
    assert res.status == "unsure"
    for tag in ("ctf-runtime-node:24", "ctf-runtime-node:22", "ctf-runtime-node:20"):
        assert f"{tag}: load: V8 rejected it" in res.notes


def test_a_node_line_that_is_not_built_does_not_hide_one_that_runs(chal, sandbox):
    put(chal, "files/app.jsc", struct.pack("<I", 0xC0DE0001) + bytes(20))
    sandbox.answers["ctf-runtime-node:24"] = sandbox.not_built
    res = rt.solve(chal, profile("allowed"))
    assert [c["tag"] for c in sandbox.calls] == ["ctf-runtime-node:24", "ctf-runtime-node:22"]
    assert res.status == "none"


def test_a_rejection_also_names_the_lines_that_could_not_be_tried(chal, sandbox):
    put(chal, "files/app.jsc", struct.pack("<I", 0xC0DE0001) + bytes(20))
    sandbox.answers["*"] = sandbox.not_built
    sandbox.answers["ctf-runtime-node:22"] = Res(line(doc("node", status="error", entries=[], strings=[],
                                                          events=[{"kind": "error", "name": "load", "text": "no"}])))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "unsure"
    assert "ctf-runtime-node:22: load: no; other images: the image ctf-runtime-node:24 is not built" in res.notes
    assert "the image ctf-runtime-node:20 is not built" in res.notes


def test_an_image_the_manifest_does_not_list_is_blocked_by_name(chal, sandbox, monkeypatch):
    put(chal, "files/a.wasm", WASM)
    monkeypatch.setattr(images, "load", lambda: [im for im in BY_NAME.values() if im.name != "runtime-wasm"])
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "blocked" and "tools/images.toml lists no image 'runtime-wasm'" in res.notes
    assert sandbox.calls == []


def test_an_unusable_image_manifest_is_blocked(chal, sandbox, monkeypatch):
    put(chal, "files/a.wasm", WASM)

    def broken():
        raise images.ImagesError("images.toml: not valid TOML")
    monkeypatch.setattr(images, "load", broken)
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "blocked" and "the image manifest is unusable (images.toml: not valid TOML)" in res.notes
    assert sandbox.calls == []


def test_a_content_hash_that_cannot_be_computed_is_blocked_not_a_crash(chal, sandbox, monkeypatch):
    put(chal, "files/a.wasm", WASM)

    def no_hash(image, root=None):
        raise images.ImagesError("py name(s) ['wasmtime'] are not pinned")
    monkeypatch.setattr(images, "content_hash", no_hash)
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "blocked" and "its content hash cannot be computed" in res.notes
    assert sandbox.calls == []


# ====================================================================================== options
def test_seconds_and_fuel_reach_the_plan(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    rt.solve(chal, profile("allowed"), seconds=7, fuel=1234)
    (call,) = sandbox.calls
    argv = call["argv"]
    assert argv[argv.index("--seconds") + 1] == "7" and argv[argv.index("--fuel") + 1] == "1234"
    assert call["seconds"] == 7 + P.GRACE_SECONDS


def test_fuel_is_not_passed_to_a_runtime_whose_fuel_is_time(chal, sandbox):
    put(chal, "files/A.class", klass())
    res = rt.solve(chal, profile("allowed"), fuel=1234)
    argv = sandbox.calls[0]["argv"]
    assert res.status == "none" and argv[argv.index("--fuel") + 1] == "0"


@pytest.mark.parametrize("opts, needle", [
    (dict(seconds=0), "seconds must be a whole number in 1..300"),
    (dict(seconds=301), "seconds must be a whole number in 1..300"),
    (dict(seconds="20"), "seconds must be a whole number, got '20'"),
    (dict(seconds=True), "seconds must be a whole number, got True"),
    (dict(fuel=0), "fuel must be a whole number in 1.."),
    (dict(fuel="lots"), "fuel must be a whole number, got 'lots'"),
    (dict(fuel=False), "fuel must be a whole number, got False"),
    (dict(probe="x" * 1025), "a probe is at most 1024 bytes"),
])
def test_an_option_out_of_bounds_is_blocked_before_anything_runs(chal, sandbox, opts, needle):
    put(chal, "files/a.wasm", WASM)
    res = rt.solve(chal, profile("allowed"), **opts)
    assert res.status == "blocked" and f"not run: bad option: {needle}" in res.notes
    assert "Found: files/a.wasm (wasm module)" in res.notes
    assert sandbox.calls == []


@pytest.mark.parametrize("opts, named", [
    ({"onyl": "files/b.wasm"}, "'onyl'"),
    ({"budget": 1}, "'budget'"),
    ({"clock": "x"}, "'clock'"),
    ({"only": "files/b.wasm", "fule": 5, "probes": "x"}, "'fule', 'probes'"),
])
def test_an_unknown_option_is_blocked_before_anything_is_looked_at(chal, sandbox, opts, named):
    put(chal, "files/a.wasm", WASM + b"a")
    put(chal, "files/b.wasm", WASM + b"b")
    res = rt.solve(chal, profile("allowed"), **opts)
    assert res.status == "blocked" and res.engine == "binary.runtime_trace"
    assert res.notes == f"not run: unknown option {named} (the options are only, probe, fuel, seconds)"
    assert sandbox.calls == []


def test_every_known_option_is_taken(chal, sandbox):
    put(chal, "files/a.wasm", WASM + b"a")
    put(chal, "files/b.wasm", WASM + b"b")
    res = rt.solve(chal, profile("allowed"), only="files/b.wasm", probe="pp", seconds=7, fuel=1234)
    assert res.status == "none"
    (call,) = sandbox.calls
    argv = call["argv"]
    assert call["members"][0][1] == WASM + b"b"
    assert argv[argv.index("--seconds") + 1] == "7" and argv[argv.index("--fuel") + 1] == "1234"
    assert "pp".encode().hex() in argv


def test_only_restricts_the_run_to_one_file(chal, sandbox):
    put(chal, "files/a.wasm", WASM + b"a")
    put(chal, "files/b.wasm", WASM + b"b")
    rt.solve(chal, profile("allowed"), only="files/b.wasm")
    assert [c["members"][0][1] for c in sandbox.calls] == [WASM + b"b"]


def test_only_on_something_unreadable_is_blocked_with_the_reason(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    res = rt.solve(chal, profile("allowed"), only="../elsewhere")
    assert res.status == "blocked"
    assert "nothing was traced. left out: ../elsewhere: not a regular file inside the challenge folder" in res.notes
    assert sandbox.calls == []


# ======================================================================================= budget
def test_artifacts_past_the_time_budget_are_named_not_run(chal, sandbox):
    for i in range(3):
        put(chal, f"files/m{i}.wasm", WASM + bytes([i]))
    clock = StepClock()

    def spend(call):
        clock.t += 40.0                                       # each run costs 40 s of the engine's budget
        return None
    sandbox.answers["*"] = spend
    res = rt.trace_challenge(chal, profile("allowed"), budget=60.0, clock=clock)
    assert [c["seconds"] for c in sandbox.calls] == [35, 15 + P.GRACE_SECONDS]
    assert res.status == "unsure"
    assert "not traced, the 60 s time budget was spent: files/m2.wasm" in res.notes
    assert "traced files/m0.wasm (wasm module), files/m1.wasm (wasm module)" in res.notes


def test_a_run_gets_no_more_than_what_is_left_of_the_budget(chal, sandbox):
    put(chal, "files/a.wasm", WASM)
    clock = StepClock()
    rt.trace_challenge(chal, profile("allowed"), budget=25.0, clock=clock)
    argv = sandbox.calls[0]["argv"]
    assert argv[argv.index("--seconds") + 1] == "20" and sandbox.calls[0]["seconds"] == 25


@pytest.mark.parametrize("budget, runs", [(10.0, 1), (9.0, 0)])
def test_a_run_is_not_started_with_less_than_the_minimum_left(chal, sandbox, budget, runs):
    put(chal, "files/a.wasm", WASM)
    res = rt.trace_challenge(chal, profile("allowed"), budget=budget, clock=StepClock())
    assert len(sandbox.calls) == runs
    assert ("not traced" in res.notes) is (runs == 0)
    assert res.status == ("unsure" if runs == 0 else "none")


# ===================================================================================== manifest
def test_the_manifest_is_a_contract_engine_that_intake_never_runs():
    m = manifest.load(REPO / "solvers" / "binary" / "runtime_trace.manifest.toml")
    assert m.id == "binary.runtime_trace" and m.capabilities[0] == "executes"
    assert m.cost_class == "heavy" and m.status == "active"
    assert m.intake is None
    assert any("reverse" in r.category for r in m.routes)
    assert all(r.files for r in m.routes), "every route is scoped by a file matcher"


def test_the_router_suggests_it_only_when_a_format_it_runs_is_in_the_files(chal):
    from ctf.engines import router
    own = [manifest.load(REPO / "solvers" / "binary" / "runtime_trace.manifest.toml")]
    put(chal, "files/notes.txt", b"nothing to run\n")
    assert router.route("reverse", "a crackme", chal / "files", manifests=own) == []
    put(chal, "files/check.wasm", WASM)
    (hit,) = router.route("reverse", "a crackme", chal / "files", manifests=own)
    assert (hit.manifest.id, hit.priority) == ("binary.runtime_trace", 36)
    (hit,) = router.route("misc", "an odd file", chal / "files", manifests=own)
    assert hit.priority == 28
    assert router.route("crypto", "an odd file", chal / "files", manifests=own) == []
    recover = manifest.load(REPO / "solvers" / "binary" / "sandbox_recover.manifest.toml")
    put(chal, "files/A.class", klass())
    ranked = [h.manifest.id for h in router.route("reverse", "x", chal / "files", manifests=own + [recover])]
    assert ranked == ["binary.sandbox_recover", "binary.runtime_trace"]      # recovery first, then the trace


@pytest.mark.parametrize("name", ["Crackme.dll", "crackme.EXE"])
def test_the_router_suggests_it_for_a_dotnet_assembly_in_reverse_only(chal, name):
    from ctf.engines import router
    own = [manifest.load(REPO / "solvers" / "binary" / "runtime_trace.manifest.toml")]
    put(chal, "files/" + name, cil())
    assert P.classify(cil(), name).runtime == "dotnet"
    (hit,) = router.route("reverse", "a .NET crackme", chal / "files", manifests=own)
    assert (hit.manifest.id, hit.priority) == ("binary.runtime_trace", 22)
    assert router.route("misc", "an odd file", chal / "files", manifests=own) == []
    assert router.route("pwn", "an odd file", chal / "files", manifests=own) == []
    put(chal, "files/check.wasm", WASM)                       # a format it runs outranks the PE guess
    (hit,) = router.route("reverse", "x", chal / "files", manifests=own)
    assert hit.priority == 36


def test_a_native_pe_routed_here_is_none_not_an_error(chal, sandbox):
    put(chal, "files/native.exe", b"MZ" + bytes(0x3A) + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + bytes(200))
    res = rt.solve(chal, profile("allowed"))
    assert res.status == "none" and sandbox.calls == []


def test_ctf_run_reaches_the_engine_and_a_shipped_event_refuses(chal, tmp_path):
    put(chal, "files/a.wasm", WASM)
    env = dict(os.environ, CTF_WORKDIR=str(tmp_path / "work"))
    r = subprocess.run([sys.executable, "-m", "ctf", "run", "--no-ledger", "binary.runtime_trace", str(chal),
                        "--event", "pink"], capture_output=True, text=True, cwd=REPO, env=env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["status"] == "blocked" and out["engine"] == "binary.runtime_trace"
    assert "rules.sandboxed_execution = 'forbidden'" in out["notes"]


# ================================================================== through the real sandbox.py
FAKE_CONTAINER = textwrap.dedent('''\
    #!{python} -I
    # ctf-docker-stub: stands in for the docker CLI. `run` does what the container would: the real
    # entry script unpacks the request from stdin and starts the real runner, here with the host's
    # interpreter on a module the test wrote.
    import json, os, subprocess, sys, tempfile
    state = json.load(open(os.environ["RT_STATE"]))
    args = sys.argv[1:]
    with open(os.environ["RT_LOG"], "a") as fh:
        fh.write(json.dumps(args) + "\\n")
    if args[:2] == ["image", "inspect"]:
        print(state["id"] + " " + state["label"])
        sys.exit(0)
    if args[:1] == ["run"]:
        at = args.index(state["id"])
        seconds, runner = args[at + 1], args[at + 2:]
        work = tempfile.mkdtemp(prefix="rt-work-")
        mapped = [state["python"] if a == "python3" else
                  state["runner"] if a == "/opt/runner/trace_runner.py" else
                  a.replace("/work/", work + "/") for a in runner]
        env = dict(os.environ, CTF_RUNTIME_WORK=work)
        p = subprocess.run(["bash", state["entry"], seconds, *mapped], stdin=sys.stdin.buffer, env=env)
        sys.exit(p.returncode)
    sys.exit(64)
    ''')


@pytest.mark.needs_tool("py:wasmtime", "bash", "tar", "timeout")
def test_the_whole_chain_engine_sandbox_entry_runner_on_our_own_module(chal, tmp_path, monkeypatch):
    import wasmtime
    enc = "".join("\\%02x" % (ord(c) ^ 0x5A) for c in FLAG)
    module = wasmtime.wat2wasm(f"""
    (module
      (memory (export "memory") 1)
      (data (i32.const 64) "{enc}")
      (func (export "decode") (result i32)
        (local $i i32)
        (loop $next
          (i32.store8 (i32.add (i32.const 64) (local.get $i))
            (i32.xor (i32.load8_u (i32.add (i32.const 64) (local.get $i))) (i32.const 90)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $next (i32.lt_u (local.get $i) (i32.const {len(FLAG)}))))
        (i32.const 64)))""")
    put(chal, "files/crackme.wasm", bytes(module))
    image = BY_NAME["runtime-wasm"]
    stub = tmp_path / "docker-stand-in"
    stub.write_text(FAKE_CONTAINER.format(python=sys.executable))
    stub.chmod(0o755)
    state, log = tmp_path / "state.json", tmp_path / "log.jsonl"
    state.write_text(json.dumps({
        "id": "sha256:" + "cd" * 32, "label": images.content_hash(image), "python": sys.executable,
        "runner": str(REPO / "docker" / "runtime" / "wasm" / "trace_runner.py"),
        "entry": str(REPO / "docker" / "runtime" / "entry.sh")}))
    monkeypatch.setenv("CTF_DOCKER", str(stub))
    monkeypatch.setenv("RT_STATE", str(state))
    monkeypatch.setenv("RT_LOG", str(log))
    monkeypatch.setattr(rt, "_SANDBOX", None)                 # the real tools/sandbox.py, loaded by path
    try:
        res = rt.solve(chal, profile("allowed"))
    finally:
        monkeypatch.setattr(rt, "_SANDBOX", None)
    assert res.status == "candidate" and res.flags == (FLAG,), res.notes
    record = json.loads((chal / res.evidence[0].path).read_text())
    assert record["trace"]["runtime"] == "wasm" and FLAG in record["trace"]["strings"]
    assert record["trace"]["fuel"]["kind"] == "instructions" and record["trace"]["fuel"]["used"] > 0
    calls = [json.loads(x) for x in log.read_text().splitlines()]
    assert [c[0] for c in calls] == ["image", "run"]
    run = calls[1]
    assert run[run.index("--network") + 1] == "none" and "-v" not in run and "--mount" not in run
    assert image.tag not in run and "sha256:" + "cd" * 32 in run


@pytest.mark.needs_tool("py:wasmtime", "bash", "tar", "timeout")
def test_through_the_real_sandbox_a_stale_image_is_blocked_and_nothing_runs(chal, tmp_path, monkeypatch):
    put(chal, "files/a.wasm", WASM)
    stub = tmp_path / "docker-stand-in"
    stub.write_text(FAKE_CONTAINER.format(python=sys.executable))
    stub.chmod(0o755)
    state, log = tmp_path / "state.json", tmp_path / "log.jsonl"
    state.write_text(json.dumps({"id": "sha256:" + "cd" * 32, "label": "0" * 64, "python": sys.executable,
                                 "runner": "unused", "entry": "unused"}))
    monkeypatch.setenv("CTF_DOCKER", str(stub))
    monkeypatch.setenv("RT_STATE", str(state))
    monkeypatch.setenv("RT_LOG", str(log))
    monkeypatch.setattr(rt, "_SANDBOX", None)
    try:
        res = rt.solve(chal, profile("allowed"))
    finally:
        monkeypatch.setattr(rt, "_SANDBOX", None)
    assert res.status == "blocked"
    assert "was built from other files" in res.notes
    assert "python -m ctf toolchain build --apply --only runtime-wasm" in res.notes
    assert [json.loads(x)[0] for x in log.read_text().splitlines()] == ["image"]
