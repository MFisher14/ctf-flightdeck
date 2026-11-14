"""B-242: the inert protocol of the runtime adapters (solvers/binary/_runtime_plans.py).

classify, build_plan, request_members and parse_trace are pure functions over bytes; every fixture
is built here by hand (magic numbers, a zip, a PE header). Nothing is run, no docker, no network.
"""
from __future__ import annotations

import io
import json
import struct
import zipfile

import pytest

import runtime_trace
from ctf.toolchain import images

P = runtime_trace.load_plans()


# ------------------------------------------------------------------------------------- fixtures
def zip_of(*names: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(zipfile.ZipInfo(n, date_time=(2026, 1, 1, 0, 0, 0)), b"x")
    return buf.getvalue()


def pe(*, clr: bool, plus: bool = False) -> bytes:
    """A PE header with (or without) the CLR runtime header directory, PE32 or PE32+."""
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = b"PE\x00\x00" + bytes(20)
    opt = bytearray(112 if plus else 96)
    struct.pack_into("<H", opt, 0, 0x20B if plus else 0x10B)
    dirs = bytearray(16 * 8)
    if clr:
        struct.pack_into("<II", dirs, 14 * 8, 0x2008, 0x48)
    return bytes(dos) + coff + bytes(opt) + bytes(dirs)


def pyc(word: int) -> bytes:
    return word.to_bytes(2, "little") + b"\r\n" + bytes(12) + b"\xe3" + bytes(8)


WASM = b"\x00asm\x01\x00\x00\x00"
CLASS = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(8)
JSC = struct.pack("<I", 0xC0DE0123) + bytes(20)


# ------------------------------------------------------------------------------------- classify
@pytest.mark.parametrize("data, name, runtime, variants, kind", [
    (WASM, "a.bin", "wasm", ("",), "module"),
    (CLASS, "A", "jvm", ("",), "class"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x2d" + bytes(8), "A", "jvm", ("",), "class"),       # major 45, the oldest
    (zip_of("META-INF/MANIFEST.MF", "com/x/Main.class"), "app.zip", "jvm", ("",), "jar"),
    (pe(clr=True), "x.bin", "dotnet", ("",), "assembly"),
    (pe(clr=True, plus=True), "x.bin", "dotnet", ("",), "assembly"),
    (pyc(3413), "m", "python", ("3.8",), "pyc"),
    (pyc(3531), "m", "python", ("3.12",), "pyc"),
    (pyc(3627), "m", "python", ("3.14",), "pyc"),
    (b"\x1bLua\x51" + bytes(8), "c", "lua", ("5.1",), "bytecode"),
    (b"\x1bLua\x54" + bytes(8), "c", "lua", ("5.4",), "bytecode"),
    (b"\x1bLJ\x02" + bytes(8), "c", "lua", ("luajit",), "bytecode"),
    (JSC, "main.JSC", "node", ("24", "22", "20"), "jsc"),
])
def test_classify_names_the_runtime_and_its_image_variants(data, name, runtime, variants, kind):
    t = P.classify(data, name)
    assert (t.runtime, t.variants, t.kind, t.note) == (runtime, variants, kind, "")


@pytest.mark.parametrize("data, name", [
    (b"", "empty"),
    (b"plain text\n", "notes.txt"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(8), "fat-macho"),      # nfat_arch 2: a universal binary
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x2c" + bytes(8), "major-44"),
    (b"\xca\xfe\xba\xbe\x00\x00", "short-class"),
    (zip_of("mimetype", "content.opf"), "book.epub"),
    (b"PK\x03\x04 not really a zip", "broken.jar"),
    (pe(clr=False), "native.exe"),
    (pe(clr=False, plus=True), "native64.exe"),
    (b"MZ" + bytes(10), "short.exe"),
    (b"hi\r\nthere, a CRLF text file", "readme.txt"),                   # 0x6968 = 26984: not a pyc magic
    (b"\x1bLu", "short-lua"),
    (JSC, "cache.bin"),                                                  # the .jsc name is part of the test
    (b"\x00\x00\x00\x00" + bytes(20), "zero.jsc"),
    (struct.pack("<I", 0xC0DE0123) + bytes(19), "short.jsc"),
    (b"console.log(1)\n", "main.js"),                                    # source needs source=True
    (b"print(1)\n", "x.lua"),
    (b"print(1)\n", "x.py"),
])
def test_classify_returns_none_for_what_no_adapter_reads(data, name):
    assert P.classify(data, name) is None


def test_a_pe_with_only_one_half_of_the_clr_directory_is_not_managed():
    for rva, size in ((0x2008, 0), (0, 0x48)):
        blob = bytearray(pe(clr=False))
        struct.pack_into("<II", blob, 0x40 + 24 + 96 + 14 * 8, rva, size)
        assert P.classify(bytes(blob), "x") is None


def test_a_truncated_pe_is_never_an_error_and_is_managed_only_once_the_clr_directory_is_whole():
    whole = pe(clr=True)
    end_of_clr = 0x40 + 24 + 96 + 15 * 8
    for n in range(len(whole) + 1):
        t = P.classify(whole[:n], "x")
        assert (t is not None) is (n >= end_of_clr), n
    whole64 = pe(clr=True, plus=True)
    end64 = 0x40 + 24 + 112 + 15 * 8
    assert P.classify(whole64[:end64], "x").runtime == "dotnet" and P.classify(whole64[:end64 - 1], "x") is None


@pytest.mark.parametrize("data, name, expect", [
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x34", "A", "jvm"),                  # 8 bytes: the version field is whole
    (b"\xca\xfe\xba\xbe\x00\x00\x00", "A", None),
    (pyc(3413)[:16], "m", "python"),                                     # 16 bytes: a whole header
    (pyc(3413)[:15], "m", None),
    ((3413).to_bytes(2, "little") + b"\n\n" + bytes(20), "m", None),     # the magic word without its CRLF
    (pyc(4000), "m", None),
    (pyc(2999), "m", None),
    (b"\x1bLua\x54", "c", "lua"),                                        # 5 bytes: the version byte is there
    (b"\x1bLua", "c", None),
    (JSC[:24], "a.jsc", "node"),
    (JSC[:23], "a.jsc", None),
])
def test_classify_at_the_length_boundaries(data, name, expect):
    t = P.classify(data, name)
    assert (t.runtime if t is not None else None) == expect


def test_targets_plans_and_traces_cannot_be_changed_after_the_fact():
    import dataclasses
    for obj, field in ((P.classify(WASM, "x"), "runtime"), (P.build_plan("wasm"), "network"),
                       (P.parse_trace(P.TRACE_MARKER.encode() + json.dumps({
                           "schema": 1, "runtime": "wasm", "runtime_version": "v", "status": "ok",
                           "fuel": {"kind": "instructions", "limit": 0, "used": 0, "exhausted": False},
                           "entries": [], "events": [], "strings": [], "notes": [], "truncated": False}).encode(),
                           "wasm"), "status")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, field, "changed")


def test_each_cpython_release_magic_maps_to_its_own_image():
    assert P.PYC_MAGIC == {3413: "3.8", 3425: "3.9", 3439: "3.10", 3495: "3.11", 3531: "3.12", 3571: "3.13",
                           3627: "3.14"}
    for word, version in P.PYC_MAGIC.items():
        assert P.classify(pyc(word), "m").variants == (version,)
        assert P.IMAGES[("python", version)] == f"runtime-python-{version}"
    for near in (3412, 3414, 3424, 3426):
        assert P.classify(pyc(near), "m").variants == ()


def test_a_pe_header_without_the_mz_signature_is_not_an_assembly():
    assert P.classify(b"ZM" + pe(clr=True)[2:], "x") is None
    assert P.classify(b"MZ" + pe(clr=True)[2:], "x").runtime == "dotnet"


def test_the_limits_are_the_ones_the_contract_states():
    assert (P.GRACE_SECONDS, P.DEFAULT_SECONDS, P.MIN_SECONDS, P.MAX_SECONDS) == (5, 30, 1, 300)
    assert (P.DEFAULT_EVENTS, P.MAX_EVENTS, P.MAX_PROBES, P.MAX_PROBE_BYTES) == (512, 4096, 8, 1024)
    assert (P.MAX_ARTIFACT_BYTES, P.MAX_REQUEST_BYTES, P.MAX_DEPS) == (64 << 20, 96 << 20, 32)
    assert (P.MAX_TRACE_BYTES, P.MAX_TRACE_TEXT) == (4 << 20, 4096)
    plan = P.build_plan("wasm")
    assert (plan.memory, plan.cpus, plan.pids, plan.seconds, plan.container_seconds) == ("768m", "1", 96, 30, 35)
    assert plan.argv[plan.argv.index("--max-events") + 1] == "512"
    assert P.TRACE_MARKER == "@@CTF-RUNTIME-TRACE@@ " and P.ENTRY == "/usr/local/bin/ctf-runtime-entry"


def test_a_pe_whose_header_offset_points_past_the_file_is_not_read():
    blob = bytearray(pe(clr=True))
    struct.pack_into("<I", blob, 0x3C, len(blob))
    assert P.classify(bytes(blob), "x") is None
    whole = pe(clr=True)
    assert P.classify(whole[:-8], "x").runtime == "dotnet"      # directory 14 is the last one still whole
    assert P.classify(whole[:-9], "x") is None                  # the CLR directory itself is cut


@pytest.mark.parametrize("data, runtime, needle", [
    (b"\x00asm\x0d\x00\x01\x00", "wasm", "0d000100"),
    (pyc(3999), "python", "3999"),
    (pyc(3000), "python", "3000"),
    (b"\x1bLua\x55" + bytes(8), "lua", "0x55"),
])
def test_a_recognised_file_no_image_reads_is_reported_not_dropped(data, runtime, needle):
    t = P.classify(data, "x")
    assert t.runtime == runtime and t.variants == ()
    assert needle in t.note


def test_the_unknown_pyc_note_lists_the_magics_that_have_an_image():
    note = P.classify(pyc(3550), "x").note
    for word, version in P.PYC_MAGIC.items():
        assert f"{word}={version}" in note


@pytest.mark.parametrize("name, runtime, variant", [
    ("main.js", "node", "24"), ("LIB.CJS", "node", "24"), ("x.lua", "lua", "5.4"), ("x.py", "python", "3.12"),
])
def test_source_text_is_classified_only_when_asked(name, runtime, variant):
    assert P.classify(b"x = 1\n", name) is None
    t = P.classify(b"x = 1\n", name, source=True)
    assert (t.runtime, t.variants, t.kind) == (runtime, (variant,), "source")


def test_source_true_does_not_claim_other_text():
    assert P.classify(b"hello\n", "notes.txt", source=True) is None
    assert P.classify(b"hello\n", "main.mjs", source=True) is None


def test_magic_wins_over_the_file_name():
    assert P.classify(WASM, "looks-like.py", source=True).runtime == "wasm"


def test_classify_takes_bytes_only():
    with pytest.raises(TypeError):
        P.classify("text", "x")
    assert P.classify(bytearray(WASM), "x").runtime == "wasm"


# ----------------------------------------------------------------------------------------- plan
def test_every_plan_image_is_in_the_manifest_and_every_runtime_image_has_a_plan():
    listed = {im.name for im in images.load()}
    assert set(P.IMAGES.values()) <= listed
    assert {n for n in listed if n.startswith("runtime-")} == set(P.IMAGES.values())


def test_every_runtime_and_variant_builds():
    for (runtime, variant), image in P.IMAGES.items():
        plan = P.build_plan(runtime, variant)
        assert (plan.runtime, plan.variant, plan.image) == (runtime, variant, image)
        assert plan.fuel_kind == P.FUEL_KIND[runtime]


def test_a_plan_is_networkless_mountless_and_unprivileged():
    plan = P.build_plan("jvm")
    assert plan.network == "none" and plan.mounts == () and plan.read_only_root is True
    assert plan.drop_capabilities == ("ALL",) and plan.user == "10001:10001"
    d = plan.to_dict()
    assert d["network"] == "none" and d["mounts"] == () and json.dumps(d)       # JSON-ready


def test_the_argv_names_the_fixed_request_paths_and_the_limits():
    plan = P.build_plan("wasm", fuel=1234, seconds=7, probes=[b"", b"AB"], max_events=99)
    assert plan.argv == ("python3", "-I", "/opt/runner/trace_runner.py", "--artifact", "/work/artifact.bin",
                         "--deps", "/work/dep", "--fuel", "1234", "--seconds", "7", "--max-events", "99",
                         "--probe-hex", "", "--probe-hex", "4142")
    assert plan.probes == ("", "4142")
    assert (plan.fuel, plan.seconds, plan.container_seconds) == (1234, 7, 7 + P.GRACE_SECONDS)


@pytest.mark.parametrize("runtime, variant, head", [
    ("python", "3.8", ("python3", "-I", "-B", "/opt/runner/trace_runner.py")),
    ("dotnet", "", ("dotnet", "/opt/runner/TraceRunner.dll")),
    ("node", "22", ("node", "--max-old-space-size=384", "/opt/runner/trace_runner.js")),
    ("lua", "5.1", ("lua5.1", "/opt/runner/trace_runner.lua")),
    ("lua", "5.4", ("lua5.4", "/opt/runner/trace_runner.lua")),
    ("lua", "luajit", ("luajit", "/opt/runner/trace_runner.lua")),
])
def test_each_runtime_starts_its_own_runner(runtime, variant, head):
    assert P.build_plan(runtime, variant).argv[:len(head)] == head


def test_the_jvm_runner_is_capped_and_headless():
    argv = P.build_plan("jvm").argv
    assert argv[0] == "java" and "-Xmx384m" in argv and "-Djava.awt.headless=true" in argv
    assert argv[argv.index("-cp") + 1:argv.index("-cp") + 3] == ("/opt/runner", "TraceRunner")


def test_instruction_runtimes_default_their_fuel_and_time_runtimes_carry_none():
    for runtime, fuel in P.DEFAULT_FUEL.items():
        variant = {"python": "3.12", "lua": "5.4"}.get(runtime, "")
        plan = P.build_plan(runtime, variant)
        assert plan.fuel == fuel and plan.fuel_kind == "instructions"
        assert plan.argv[plan.argv.index("--fuel") + 1] == str(fuel)
    for runtime, variant in (("jvm", ""), ("dotnet", ""), ("node", "24")):
        plan = P.build_plan(runtime, variant)
        assert plan.fuel == 0 and plan.fuel_kind == "time"
        assert P.build_plan(runtime, variant, fuel=0).fuel == 0


@pytest.mark.parametrize("kw, msg", [
    (dict(runtime="ruby"), "unknown runtime 'ruby'"),
    (dict(runtime="python", variant="2.7"), "no variant '2.7'"),
    (dict(runtime="python", variant=""), "no variant ''"),
    (dict(runtime="wasm", variant="1"), "no variant '1'"),
    (dict(runtime="wasm", seconds=0), "seconds must be a whole number in 1..300"),
    (dict(runtime="wasm", seconds=301), "seconds must be a whole number in 1..300"),
    (dict(runtime="wasm", seconds=2.5), "seconds must be a whole number"),
    (dict(runtime="wasm", seconds=True), "seconds must be a whole number"),
    (dict(runtime="wasm", fuel=0), "fuel must be a whole number in 1.."),
    (dict(runtime="wasm", fuel=10 ** 12 + 1), "fuel must be a whole number in 1.."),
    (dict(runtime="wasm", fuel="many"), "fuel must be a whole number"),
    (dict(runtime="jvm", fuel=5), "has no instruction counter"),
    (dict(runtime="wasm", max_events=0), "max_events must be a whole number in 1..4096"),
    (dict(runtime="wasm", max_events=4097), "max_events must be a whole number in 1..4096"),
    (dict(runtime="wasm", probes=[b"x"] * 9), "at most 8 probes, got 9"),
    (dict(runtime="wasm", probes=[b"x" * 1025]), "a probe is at most 1024 bytes"),
    (dict(runtime="wasm", probes=["text"]), "a probe is at most 1024 bytes"),
])
def test_a_plan_out_of_bounds_is_refused(kw, msg):
    kw = dict(kw)
    runtime = kw.pop("runtime")
    variant = kw.pop("variant", {"python": "3.12"}.get(runtime, ""))
    with pytest.raises(P.PlanError, match=msg.replace("(", r"\(").replace(")", r"\)")):
        P.build_plan(runtime, variant, **kw)


def test_the_bounds_themselves_are_accepted():
    plan = P.build_plan("wasm", seconds=300, fuel=10 ** 12, max_events=4096, probes=[b"x" * 1024] * 8)
    assert (plan.seconds, plan.fuel, len(plan.probes)) == (300, 10 ** 12, 8)
    assert P.build_plan("wasm", seconds=1, fuel=1, max_events=1).container_seconds == 1 + P.GRACE_SECONDS


# -------------------------------------------------------------------------------------- request
def test_request_members_use_fixed_names_only():
    got = P.request_members(b"ART", [b"d0", b"d1"])
    assert got == [("artifact.bin", b"ART"), ("dep/000.bin", b"d0"), ("dep/001.bin", b"d1")]
    assert P.request_members(bytearray(b"A")) == [("artifact.bin", b"A")]


def test_request_caps(monkeypatch):
    with pytest.raises(P.PlanError, match="non-empty bytes"):
        P.request_members(b"")
    with pytest.raises(P.PlanError, match="non-empty bytes"):
        P.request_members("text")
    with pytest.raises(P.PlanError, match="at most 32 dependencies, got 33"):
        P.request_members(b"A", [b"d"] * 33)
    assert len(P.request_members(b"A", [b"d"] * 32)) == 33
    monkeypatch.setattr(P, "MAX_ARTIFACT_BYTES", 4)
    monkeypatch.setattr(P, "MAX_REQUEST_BYTES", 6)
    with pytest.raises(P.PlanError, match="the artifact is 5 bytes, over the 4 byte cap"):
        P.request_members(b"12345")
    assert P.request_members(b"1234", [b"56"])                      # exactly at both caps
    with pytest.raises(P.PlanError, match="the request is 7 bytes, over the 6 byte cap"):
        P.request_members(b"1234", [b"567"])


# ---------------------------------------------------------------------------------------- trace
def doc(**over) -> dict:
    d = {"schema": 1, "runtime": "wasm", "runtime_version": "wasmtime-py 50.0.1", "status": "ok",
         "fuel": {"kind": "instructions", "limit": 1000, "used": 10, "exhausted": False},
         "entries": [{"name": "check", "signature": "(i32) -> (i32)"}],
         "events": [{"kind": "call", "name": "check", "args": "zeros", "result": "0"}],
         "strings": ["hello"], "notes": [], "truncated": False}
    d.update(over)
    return d


def line(d, prefix=b"") -> bytes:
    return prefix + P.TRACE_MARKER.encode() + json.dumps(d).encode() + b"\n"


def test_a_valid_trace_is_parsed_into_typed_fields():
    t = P.parse_trace(line(doc()), "wasm")
    assert (t.runtime, t.runtime_version, t.status) == ("wasm", "wasmtime-py 50.0.1", "ok")
    assert (t.fuel_kind, t.fuel_limit, t.fuel_used, t.fuel_exhausted) == ("instructions", 1000, 10, False)
    assert t.entries == (("check", "(i32) -> (i32)"),)
    assert t.events == ({"kind": "call", "name": "check", "args": "zeros", "result": "0"},)
    assert t.strings == ("hello",) and t.notes == () and t.truncated is False
    assert t.to_dict() == doc()


def test_the_last_trace_line_wins_and_other_output_is_ignored():
    out = b"noise the artifact printed\n" + line(doc(strings=["forged first"])) + b"more noise\n" + line(doc())
    assert P.parse_trace(out, "wasm").strings == ("hello",)


def test_texts_and_errors_cover_strings_and_event_fields():
    t = P.parse_trace(line(doc(events=[
        {"kind": "call", "name": "f", "args": "probe 0", "error": "boom"},
        {"kind": "call", "name": "g", "args": "", "result": "fine"},
        {"kind": "error", "name": "load", "text": "bad module"},
        {"kind": "output", "stream": "stdout", "text": "printed", "error": "not a call"}])), "wasm")
    assert t.texts() == ["hello", "f", "probe 0", "boom", "g", "", "fine", "load", "bad module", "stdout",
                         "printed", "not a call"]
    assert t.errors() == ["f(probe 0): boom", "load: bad module"]      # a call that returned is not an error


def test_trace_values_at_their_lower_bounds_are_accepted():
    zero = doc(fuel={"kind": "instructions", "limit": 0, "used": 0, "exhausted": False},
               events=[{"kind": "a"}, {"kind": "k" * 32},
                       {"kind": "call", **{f"k{i}": "v" for i in range(7)}}])
    t = P.parse_trace(line(zero), "wasm")
    assert (t.fuel_limit, t.fuel_used) == (0, 0)
    assert [e["kind"] for e in t.events] == ["a", "k" * 32, "call"] and len(t.events[2]) == 8
    with pytest.raises(P.TraceError, match="not an object with a kind"):
        P.parse_trace(line(doc(events=[{"kind": "k" * 33}])), "wasm")
    with pytest.raises(P.TraceError, match="not an object with a kind"):
        P.parse_trace(line(doc(events=[{"kind": ""}])), "wasm")


@pytest.mark.parametrize("stdout, msg", [
    (b"", "printed no trace line"),
    (b"just output\n", "printed no trace line"),
    (b" " + line(doc()), "printed no trace line"),                       # the marker must start the line
    (P.TRACE_MARKER.encode() + b"{not json\n", "not JSON"),
    (P.TRACE_MARKER.encode() + b"[" * 100000 + b"\n", "not JSON"),
    (P.TRACE_MARKER.encode() + b"\xff\xfe\n", "not JSON"),
    (P.TRACE_MARKER.encode() + b"[1]\n", "not schema 1"),
])
def test_output_that_is_not_a_trace_is_refused(stdout, msg):
    with pytest.raises(P.TraceError, match=msg):
        P.parse_trace(stdout, "wasm")


@pytest.mark.parametrize("over, msg", [
    (dict(schema=2), "not schema 1"),
    (dict(runtime="jvm"), "written by runtime 'jvm', not 'wasm'"),
    (dict(status="fine"), "status 'fine' is not one of"),
    (dict(fuel={"kind": "time", "limit": 1, "used": 1, "exhausted": False}), "fuel is not 'instructions' fuel"),
    (dict(fuel="lots"), "fuel is not 'instructions' fuel"),
    (dict(fuel={"kind": "instructions", "limit": -1, "used": 1, "exhausted": False}), "fuel.limit is not a whole number"),
    (dict(fuel={"kind": "instructions", "limit": 1, "used": "1", "exhausted": False}), "fuel.used is not a whole number"),
    (dict(fuel={"kind": "instructions", "limit": True, "used": 1, "exhausted": False}), "fuel.limit is not a whole number"),
    (dict(fuel={"kind": "instructions", "limit": 1, "used": 1, "exhausted": "no"}), "must be true or false"),
    (dict(truncated=0), "must be true or false"),
    (dict(entries={}), "entries is not a list"),
    (dict(entries=[{"name": "f"}]), "not {name, signature}"),
    (dict(entries=[{"name": "f", "signature": 1}]), "an entry signature is not a string"),
    (dict(entries=[{"name": "f", "signature": "s", "extra": "x"}]), "not {name, signature}"),
    (dict(events="x"), "events is not a list"),
    (dict(events=[{"name": "f"}]), "not an object with a kind"),
    (dict(events=[{"kind": "Call"}]), "not an object with a kind"),
    (dict(events=[{"kind": "call", "result": 5}]), "event field 'result' is not a string"),
    (dict(events=[{"kind": "call", **{f"k{i}": "v" for i in range(8)}}]), "at most 7 fields"),
    (dict(events=[["call"]]), "not an object with a kind"),
    (dict(strings="hello"), "strings is not a list"),
    (dict(strings=[1]), "an item of strings is not a string"),
    (dict(strings=["x" * 4097]), "longer than 4096 characters"),
    (dict(notes=None), "notes is not a list"),
    (dict(runtime_version=None), "runtime_version is not a string"),
])
def test_a_trace_of_the_wrong_shape_is_refused(over, msg):
    with pytest.raises(P.TraceError, match=msg):
        P.parse_trace(line(doc(**over)), "wasm")


def test_trace_caps_hold_at_the_boundary():
    ok = doc(strings=["s"] * 1024, notes=["n"] * 256, entries=[{"name": "f", "signature": "s"}] * 1024,
             events=[{"kind": "call"}] * 4096)
    t = P.parse_trace(line(ok), "wasm")
    assert (len(t.strings), len(t.notes), len(t.entries), len(t.events)) == (1024, 256, 1024, 4096)
    assert P.parse_trace(line(doc(strings=["x" * 4096])), "wasm").strings == ("x" * 4096,)
    for over, msg in ((dict(strings=["s"] * 1025), "strings has 1025 items"),
                      (dict(notes=["n"] * 257), "notes has 257 items"),
                      (dict(entries=[{"name": "f", "signature": "s"}] * 1025), "entries is not a list of at most 1024"),
                      (dict(events=[{"kind": "call"}] * 4097), "events is not a list of at most 4096")):
        with pytest.raises(P.TraceError, match=msg):
            P.parse_trace(line(doc(**over)), "wasm")


def test_an_oversized_trace_line_is_refused(monkeypatch):
    monkeypatch.setattr(P, "MAX_TRACE_BYTES", len(json.dumps(doc())))
    assert P.parse_trace(line(doc()), "wasm").status == "ok"            # exactly at the cap
    monkeypatch.setattr(P, "MAX_TRACE_BYTES", len(json.dumps(doc())) - 1)
    with pytest.raises(P.TraceError, match="over the .* byte cap"):
        P.parse_trace(line(doc()), "wasm")


def test_parse_trace_takes_bytes():
    with pytest.raises(TypeError):
        P.parse_trace("text", "wasm")


@pytest.mark.parametrize("runtime, kind", sorted(P.FUEL_KIND.items()))
def test_each_runtime_must_report_its_own_kind_of_fuel(runtime, kind):
    good = doc(runtime=runtime, fuel={"kind": kind, "limit": 5, "used": 1, "exhausted": True})
    t = P.parse_trace(line(good), runtime)
    assert t.fuel_kind == kind and t.fuel_exhausted is True
    other = "time" if kind == "instructions" else "instructions"
    bad = doc(runtime=runtime, fuel={"kind": other, "limit": 5, "used": 1, "exhausted": True})
    with pytest.raises(P.TraceError, match="fuel"):
        P.parse_trace(line(bad), runtime)
