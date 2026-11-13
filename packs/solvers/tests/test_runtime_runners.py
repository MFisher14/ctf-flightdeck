"""B-242: the in-container runners of docker/runtime/, run for real on fixtures written here.

Each ctf-runtime-* image bakes one runner (wasm, python, lua, jvm, dotnet, node) and the entry script.
The images cannot be built from build work, so these tests run the same runner files directly with
the host's own interpreter on OUR OWN sources (WAT, Python, Lua, Java, C#, JavaScript compiled or
written in the test): never a delivered file, never a container, no network. Every invocation is the
whole argv of _runtime_plans.build_plan (the interpreter and its flags too), with /opt/runner and the
interpreter's name mapped to the host's, and every output goes through parse_trace, so the plan, the
runner and the parser are held to one protocol. A runtime the host lacks is reported NOT RUN.

Fuel: wasm, python and lua count instructions, so their tests have no clock in them. The JVM, .NET
and Node runners bound a call by wall time; where a test needs that limit to fire, the fixture never
returns (the limit is the expected outcome at any machine load), and every other run gets a budget
far above what it needs.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import marshal
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import runtime_trace

P = runtime_trace.load_plans()
REPO = Path(__file__).resolve().parents[1]
RUNTIME = REPO / "docker" / "runtime"
TOKEN = "ctf-selftest-ok"
FLAG = "RT{decoded_at_run_time}"
GENEROUS = 240                      # seconds: a time budget no healthy run comes near
# A safety net, not a performance bound: a runner whose fuel or time stop broke would otherwise hang
# the suite. A healthy run ends far below it at any machine load.
SAFETY = 900


def xor(text: str) -> list[int]:
    return [ord(c) ^ 0x5A for c in text]


# The interpreter a plan names, as the host has it (the image's python3 is this test's own Python).
HOST_INTERPRETER = {"python3": sys.executable, "lua5.4": "lua5.4" if shutil.which("lua5.4") else "lua"}


def plan_argv(runtime: str, variant: str, artifact: Path, deps: Path | None = None, *,
              runner_dir: Path | None = None, **kw) -> list[str]:
    """build_plan's whole argv (interpreter, its flags, the runner, the options), with /opt/runner
    mapped to ``runner_dir`` (default: the runner's folder in docker/runtime), the interpreter to the
    host's and the container's /work paths to the test's files."""
    base = Path(runner_dir) if runner_dir is not None else RUNTIME / runtime
    out = []
    for a in P.build_plan(runtime, variant, **kw).argv:
        if a == "/opt/runner":
            a = str(base)
        elif a.startswith("/opt/runner/"):
            a = str(base / a[len("/opt/runner/"):])
        out.append(a)
    out[0] = HOST_INTERPRETER.get(out[0], out[0])
    out[out.index("--artifact") + 1] = str(artifact)
    out[out.index("--deps") + 1] = str(deps if deps is not None else artifact.parent / "no-deps")
    return out


def trace_of(runtime: str, argv: list[str], *, env: dict | None = None, timeout: float = SAFETY):
    """(exit status, validated Trace) of one runner process."""
    try:
        r = subprocess.run(argv, capture_output=True, env=env, stdin=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise AssertionError(f"the runner did not end within {timeout} s (a broken stop?): "
                             f"stdout {(e.stdout or b'')[-400:]!r}") from None
    try:
        return r.returncode, P.parse_trace(r.stdout, runtime)
    except P.TraceError as e:
        raise AssertionError(f"{e}; exit {r.returncode}; stderr: {r.stderr[-800:]!r}; stdout: {r.stdout[-400:]!r}")


def events(trace, kind: str, name: str | None = None) -> list[dict]:
    return [e for e in trace.events if e["kind"] == kind and (name is None or e.get("name") == name)]


def results(trace, name: str) -> dict:
    """{args: result-or-error} of every call event of one entry point."""
    return {e.get("args", ""): e.get("result", "ERROR " + e.get("error", "")) for e in events(trace, "call", name)}


# =================================================================================== self-tests
# The fixtures of docker/runtime/selftest are what each Dockerfile runs at build time and greps for
# TOKEN. The token must not be written out in any of them: it has to be computed by the fixture.
def test_no_selftest_fixture_spells_the_token_out():
    files = sorted((RUNTIME / "selftest").iterdir())
    assert len(files) >= 6
    for f in files:
        assert TOKEN not in f.read_text(encoding="utf-8"), f.name


def test_every_dockerfile_runs_its_self_test_and_greps_the_token():
    dockerfiles = sorted(RUNTIME.glob("*/Dockerfile"))
    assert [d.parent.name for d in dockerfiles] == ["dotnet", "jvm", "lua", "node", "python", "wasm"]
    for d in dockerfiles:
        text = d.read_text(encoding="utf-8")
        assert re.search(r"RUN [^#]*grep -q '" + TOKEN + "'", text, re.S), d
        assert "USER 10001:10001" in text and "COPY entry.sh /usr/local/bin/ctf-runtime-entry" in text, d
        assert "EXPOSE" not in text and "VOLUME" not in text, d


# ========================================================================================= wasm
wasm_only = pytest.mark.needs_tool("py:wasmtime")


def wat(text: str, tmp: Path, name: str = "artifact.bin") -> Path:
    import wasmtime
    p = tmp / name
    p.write_bytes(bytes(wasmtime.wat2wasm(text)))
    return p


def run_wasm(artifact: Path, **kw):
    return trace_of("wasm", plan_argv("wasm", "", artifact, **kw))


DECODER_WAT = """
(module
  (import "env" "log" (func $log (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "%s")
  (func (export "decode") (result i32)
    (local $i i32)
    (loop $next
      (i32.store8 (i32.add (i32.const 64) (local.get $i))
        (i32.xor (i32.load8_u (i32.add (i32.const 64) (local.get $i))) (i32.const 90)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $next (i32.lt_u (local.get $i) (i32.const %d))))
    (call $log (i32.const 64))
    (i32.const 64))
  (func (export "first_is_R") (param $p i32) (result i32)
    (i32.eq (i32.load8_u (local.get $p)) (i32.const 82)))
  (func (export "second_arg") (param i32 i32) (result i32) (local.get 1)))
""" % ("".join("\\%02x" % b for b in xor(FLAG)), len(FLAG))


@wasm_only
def test_wasm_selftest_fixture_yields_the_token(tmp_path):
    rc, t = run_wasm(wat((RUNTIME / "selftest" / "selftest.wat").read_text(), tmp_path))
    assert rc == 0 and t.status == "ok"
    assert TOKEN in t.strings and ("decode", "() -> (i32)") in t.entries


@wasm_only
def test_wasm_reports_a_string_decoded_in_memory_and_the_import_it_called(tmp_path):
    rc, t = run_wasm(wat(DECODER_WAT, tmp_path), probes=[b"Rprobe", b"zzz"])
    assert rc == 0 and t.status == "ok" and t.fuel_kind == "instructions"
    assert FLAG in t.strings
    assert events(t, "import", "env.log") and events(t, "import_call", "env.log")[0]["args"] == "64"
    assert results(t, "decode") == {"zeros": "64"}
    assert 0 < t.fuel_used < t.fuel_limit and not t.fuel_exhausted


@wasm_only
def test_wasm_places_each_probe_in_memory_and_passes_its_address_and_length(tmp_path):
    rc, t = run_wasm(wat(DECODER_WAT, tmp_path), probes=[b"Rprobe", b"zzz"])
    first = results(t, "first_is_R")
    assert first["zeros"] == "0"
    assert {k.split(" at ")[0]: v for k, v in first.items() if k != "zeros"} == {"probe 0": "1", "probe 1": "0"}
    second = results(t, "second_arg")
    assert {k.split(" at ")[0]: v for k, v in second.items() if k != "zeros"} == {"probe 0": "6", "probe 1": "3"}


@wasm_only
def test_wasm_a_function_that_never_returns_uses_its_share_and_the_rest_is_still_traced(tmp_path):
    src = '(module (func (export "spin") (loop $l (br $l))) (func (export "after") (result i32) (i32.const 7)))'
    rc, t = run_wasm(wat(src, tmp_path), fuel=80000)
    assert rc == 0 and t.status == "partial"
    assert results(t, "spin") == {"zeros": "ERROR out of fuel"}
    assert results(t, "after") == {"zeros": "7"}
    assert not t.fuel_exhausted and 10000 <= t.fuel_used < 80000      # one share (an eighth) was burnt


@wasm_only
def test_wasm_the_whole_budget_ends_the_run(tmp_path):
    spins = "".join(f'(func (export "spin{i}") (loop $l (br $l)))' for i in range(9))
    rc, t = run_wasm(wat(f"(module {spins})", tmp_path), fuel=8000)
    assert rc == 0 and t.status == "partial" and t.fuel_exhausted and t.fuel_used == 8000
    called = [e["name"] for e in events(t, "call")]
    assert called == [f"spin{i}" for i in range(8)]                    # the ninth was never started


@wasm_only
def test_wasm_wasi_command_runs_with_captured_output_and_no_files(tmp_path):
    src = """
    (module
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "path_open"
        (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 8) "hello from wasi\\n")
      (data (i32.const 40) "secret.txt")
      (func (export "_start")
        (i32.store (i32.const 100) (i32.const 8))
        (i32.store (i32.const 104) (i32.const 16))
        (drop (call $fd_write (i32.const 1) (i32.const 100) (i32.const 1) (i32.const 200)))
        (if (i32.eqz (call $path_open (i32.const 3) (i32.const 0) (i32.const 40) (i32.const 10)
                       (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 300)))
          (then (unreachable)))))
    """
    rc, t = run_wasm(wat(src, tmp_path))
    assert rc == 0 and t.status == "ok"
    assert [e["text"] for e in events(t, "output") if e["stream"] == "stdout"][0] == "hello from wasi\n"
    assert "hello from wasi" in t.strings
    assert all("error" not in e for e in events(t, "call", "_start"))      # path_open failed: no preopen


@wasm_only
def test_wasm_a_non_numeric_parameter_is_named_and_not_called(tmp_path):
    rc, t = run_wasm(wat('(module (func (export "takes_ref") (param externref)))', tmp_path))
    assert rc == 0 and events(t, "call") == []
    assert t.notes == ("takes_ref takes a non-numeric parameter: not called",)


@wasm_only
def test_wasm_bytes_that_are_not_a_module_are_a_load_error(tmp_path):
    bad = tmp_path / "artifact.bin"
    bad.write_bytes(b"\x00asm\x01\x00\x00\x00\xff\xff")
    rc, t = run_wasm(bad)
    assert rc == 0 and t.status == "error" and t.entries == () and t.fuel_used == 0
    assert events(t, "error", "load")


@wasm_only
def test_wasm_a_trapping_start_function_is_an_error_not_a_crash(tmp_path):
    rc, t = run_wasm(wat("(module (func $s (unreachable)) (start $s))", tmp_path))
    assert rc == 0 and t.status == "error" and events(t, "error", "instantiate")


# ======================================================================================= python
def pyc_of(source: str, tmp: Path, name: str = "artifact.bin", magic: bytes | None = None) -> Path:
    p = tmp / name
    code = compile(source, "fixture.py", "exec")
    p.write_bytes((magic or importlib.util.MAGIC_NUMBER) + bytes(12) + marshal.dumps(code))
    return p


def run_python(artifact: Path, **kw):
    variant = "%d.%d" % sys.version_info[:2]
    if ("python", variant) not in P.IMAGES:
        variant = P.DEFAULT_PYTHON
    return trace_of("python", plan_argv("python", variant, artifact, **kw))


CRACK_PY = '''
import sys
ENC = %r
secret = "".join(chr(x ^ 0x5a) for x in ENC)
def check(s):
    return s == secret
def banner():
    return "banner-%%d" %% len(secret)
line = input("key? ")
print("correct" if check(line) else "wrong: " + line)
if line == "quit":
    sys.exit(3)
''' % (xor(FLAG),)


def test_python_selftest_fixture_yields_the_token(tmp_path):
    rc, t = run_python(pyc_of((RUNTIME / "selftest" / "selftest.py").read_text(), tmp_path))
    assert rc == 0 and t.status == "ok" and TOKEN in t.strings
    assert ("check", "code/1") in t.entries


def test_python_reports_the_global_the_module_built_and_what_each_probe_does(tmp_path):
    rc, t = run_python(pyc_of(CRACK_PY, tmp_path), probes=[b"nope", FLAG.encode(), b"quit"])
    assert rc == 0 and t.status == "ok" and t.fuel_kind == "instructions"
    assert {"kind": "global", "name": "secret", "value": FLAG} in t.events
    assert results(t, "check") == {"probe 0": "False", "probe 1": "True", "probe 2": "False"}
    assert results(t, "banner") == {"": "banner-%d" % len(FLAG)}
    out = [e["text"] for e in events(t, "output")]
    assert out == ["key? wrong: nope\n", "key? correct\n", "key? wrong: quit\n"]
    assert [e["text"] for e in events(t, "exit")] == ["3"]
    assert events(t, "import", "sys")
    assert FLAG in t.strings and 0 < t.fuel_used < t.fuel_limit


def test_python_a_module_that_reads_no_input_runs_once(tmp_path):
    rc, t = run_python(pyc_of("value = 'built-' + str(6 * 7)\nprint(value)\n", tmp_path), probes=[b"a", b"b", b"c"])
    assert rc == 0 and t.status == "ok"
    assert len(events(t, "output")) == 1 and "built-42" in t.strings


def test_python_a_pyc_of_another_version_is_reported_and_never_unmarshalled(tmp_path):
    other = (3413 if sys.version_info[:2] != (3, 8) else 3425).to_bytes(2, "little") + b"\r\n"
    rc, t = run_python(pyc_of("print('ran')\n", tmp_path, magic=other))
    assert rc == 0 and t.status == "error" and t.fuel_used == 0 and events(t, "output") == []
    text = events(t, "error", "load")[0]["text"]
    own = int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little")
    assert f"magic {int.from_bytes(other[:2], 'little')}" in text and f"reads magic {own}" in text


def test_python_a_body_that_does_not_unmarshal_is_a_load_error(tmp_path):
    bad = tmp_path / "artifact.bin"
    bad.write_bytes(importlib.util.MAGIC_NUMBER + bytes(12) + b"\xff\xfe\xfd")
    rc, t = run_python(bad)
    assert rc == 0 and t.status == "error" and "unmarshal failed" in events(t, "error", "load")[0]["text"]
    notcode = tmp_path / "list.bin"
    notcode.write_bytes(importlib.util.MAGIC_NUMBER + bytes(12) + marshal.dumps([1, 2]))
    rc, t = run_python(notcode)
    assert t.status == "error" and "not a code object" in events(t, "error", "load")[0]["text"]


def test_python_source_text_is_compiled_and_run(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("built = 'from-' + 'source'\n")
    rc, t = run_python(src)
    assert rc == 0 and t.status == "ok" and "from-source" in t.strings


def test_python_a_function_that_never_returns_uses_its_share_and_the_rest_is_still_traced(tmp_path):
    src = "def spin():\n    while True:\n        pass\ndef zz():\n    return 7\n"
    rc, t = run_python(pyc_of(src, tmp_path), fuel=4000)
    assert rc == 0 and t.status == "partial" and not t.fuel_exhausted
    assert results(t, "spin") == {"": "ERROR stopped: it used its share of the fuel"}
    assert results(t, "zz") == {"": "7"}
    assert 500 <= t.fuel_used < 4000


def test_python_the_module_body_is_counted_too(tmp_path):
    rc, t = run_python(pyc_of("while True:\n    pass\n", tmp_path), fuel=4000)
    assert t.status == "partial" and t.fuel_used == 500
    assert events(t, "error", "module")[0]["text"] == "stopped: it used its share of the fuel"


def test_python_the_whole_budget_ends_the_run(tmp_path):
    src = "".join(f"def s{i}():\n    while True:\n        pass\n" for i in range(9))
    rc, t = run_python(pyc_of(src, tmp_path), fuel=4000)
    assert rc == 0 and t.status == "partial" and t.fuel_exhausted and t.fuel_used == 4000
    called = [e["name"] for e in events(t, "call")]
    assert called[-1] == "s7" and "s8" not in called
    assert results(t, "s7") == {"": "ERROR out of fuel"}


@pytest.mark.skipif(not hasattr(sys, "monitoring"), reason="needs sys.monitoring (Python 3.12+): on an older "
                    "CPython tracing stops after the first raise, so this fixture would not end")
def test_python_code_that_catches_the_fuel_stop_cannot_go_on(tmp_path):
    src = "print('before')\nwhile True:\n    try:\n        pass\n    except BaseException:\n        pass\n"
    rc, t = run_python(pyc_of(src, tmp_path), fuel=4000)
    assert rc == 0 and t.status == "partial" and not t.fuel_exhausted
    assert events(t, "error", "module")[0]["text"] == "stopped: it used its share of the fuel"
    assert 500 <= t.fuel_used < 600            # the stop came back at the very next instructions
    assert [e["text"] for e in events(t, "output")] == ["before\n"]


def test_python_open_is_recorded_with_the_name_asked_for(tmp_path):
    src = ("try:\n    open('/nonexistent-ctf-runtime/secret.txt')\nexcept OSError as e:\n"
           "    failed = type(e).__name__\n")
    rc, t = run_python(pyc_of(src, tmp_path))
    assert rc == 0 and t.status == "ok"
    assert events(t, "open") == [{"kind": "open", "name": "/nonexistent-ctf-runtime/secret.txt"}]
    assert {"kind": "global", "name": "failed", "value": "FileNotFoundError"} in t.events


def test_python_an_exception_in_the_artifact_is_a_finding_not_a_crash(tmp_path):
    rc, t = run_python(pyc_of("def boom(s):\n    raise ValueError('no ' + s)\n", tmp_path), probes=[b"key"])
    assert rc == 0 and t.status == "partial"
    assert results(t, "boom") == {"probe 0": "ERROR ValueError: no key"}


# ========================================================================================== lua
lua_only = pytest.mark.needs_tool("lua")


def run_lua(artifact: Path, *, timeout: float = SAFETY, **kw):
    return trace_of("lua", plan_argv("lua", "5.4", artifact, **kw), timeout=timeout)


CRACK_LUA = '''
local enc = {%s}
local t = {}
for i, x in ipairs(enc) do t[i] = string.char((x + 166) %% 256) end
secret = table.concat(t)
function check(s) return s == secret end
function banner() return "banner-" .. #secret end
api = { version = "v1.2", greet = function(n) return "hi " .. tostring(n) end }
local gen = load("return 'generated-' .. 6 * 7")
print("gen", gen())
print("require", pcall(require, "socket"))
io.write("key? ")
local line = io.read("l")
print(check(line) and "correct" or ("wrong: " .. tostring(line)))
if line == "quit" then os.exit(3) end
return 42, "ret"
''' % ", ".join(str((ord(c) + 90) % 256) for c in FLAG)


@lua_only
def test_lua_selftest_fixture_yields_the_token(tmp_path):
    rc, t = run_lua(RUNTIME / "selftest" / "selftest.lua")
    assert rc == 0 and t.status == "ok" and TOKEN in t.strings
    assert ("check", "function/1") in t.entries


@lua_only
def test_lua_reports_globals_generated_chunks_and_what_each_probe_does(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text(CRACK_LUA)
    rc, t = run_lua(src, probes=[b"nope", FLAG.encode(), b"quit"])
    assert rc == 0 and t.status == "ok" and t.fuel_kind == "instructions"
    assert {"kind": "global", "name": "secret", "value": FLAG} in t.events
    assert {"kind": "global", "name": "api.version", "value": "v1.2"} in t.events
    assert results(t, "check") == {"probe 0": "false", "probe 1": "true", "probe 2": "false"}
    assert results(t, "api.greet")["probe 1"] == "hi " + FLAG
    assert results(t, "banner") == {"": "banner-%d" % len(FLAG)}
    assert events(t, "chunk")[0]["text"] == "return 'generated-' .. 6 * 7"
    assert events(t, "require", "socket")
    out = [e["text"] for e in events(t, "output")]
    assert "gen\tgenerated-42" in out and "wrong: nope" in out and "correct" in out and "wrong: quit" in out
    assert [e["text"] for e in events(t, "exit")] == ["3"]
    assert [e["value"] for e in events(t, "return")][:2] == ["42", "ret"]
    assert FLAG in t.strings and 0 < t.fuel_used < t.fuel_limit


@lua_only
def test_lua_the_sandbox_table_gives_no_file_and_no_process(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("opened = tostring(io.open('/etc/passwd'))\nhas_popen = tostring(io.popen)\n"
                   "has_execute = tostring(os.execute)\nhas_debug = tostring(debug)\n")
    rc, t = run_lua(src)
    values = {e["name"]: e["value"] for e in events(t, "global")}
    assert values == {"opened": "nil", "has_popen": "nil", "has_execute": "nil", "has_debug": "nil"}
    assert events(t, "refused", "io.open")[0]["text"] == "/etc/passwd"


@lua_only
@pytest.mark.needs_tool("luac")
def test_lua_bytecode_runs_and_another_versions_bytecode_is_a_load_error(tmp_path):
    src = tmp_path / "src.lua"
    src.write_text(CRACK_LUA)
    out = tmp_path / "artifact.bin"
    subprocess.run(["luac", "-s", "-o", str(out), str(src)], check=True)
    assert P.classify(out.read_bytes(), "x").runtime == "lua"
    rc, t = run_lua(out, probes=[FLAG.encode()])
    assert rc == 0 and t.status == "ok" and results(t, "check") == {"probe 0": "true"}
    blob = bytearray(out.read_bytes())
    blob[4] = 0x51                                         # claims to be Lua 5.1 bytecode
    bad = tmp_path / "bad.bin"
    bad.write_bytes(bytes(blob))
    rc, t = run_lua(bad)
    assert rc == 0 and t.status == "error" and t.fuel_used == 0
    assert "version mismatch" in events(t, "error", "load")[0]["text"]


@lua_only
def test_lua_a_function_that_never_returns_uses_its_share_and_the_rest_is_still_traced(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("function spin() while true do end end\nfunction zz() return 7 end\n")
    rc, t = run_lua(src, fuel=80000)
    assert rc == 0 and t.status == "partial" and not t.fuel_exhausted
    assert results(t, "spin") == {"": "ERROR stopped: it used its share of the fuel"}
    assert results(t, "zz") == {"": "7"}
    assert 10000 <= t.fuel_used < 80000


@lua_only
def test_lua_a_coroutine_does_not_escape_the_fuel(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("function inside() local co = coroutine.wrap(function() while true do end end) co() end\n"
                   "function created() local co = coroutine.create(function() while true do end end)\n"
                   "  local ok, err = coroutine.resume(co) error(err, 0) end\n")
    rc, t = run_lua(src, fuel=80000)
    assert rc == 0 and t.status == "partial"
    assert results(t, "inside") == {"": "ERROR stopped: it used its share of the fuel"}
    assert results(t, "created") == {"": "ERROR stopped: it used its share of the fuel"}


@lua_only
@pytest.mark.parametrize("catch", [
    "pcall(function() while true do end end)",
    "xpcall(function() while true do end end, function(e) return e end)",
    "xpcall(function() while true do end end, function(e) return 'swallowed' end)",
    "xpcall(function(a) while a do end end, function(e) return e end, true)",
])
def test_lua_a_protected_call_does_not_catch_the_fuel_stop(tmp_path, catch):
    # Instruction fuel, no clock: without the stop passed on, spin() would never end (SAFETY fails it).
    src = tmp_path / "artifact.bin"
    src.write_text(f"function spin() while true do {catch} end end\nfunction zz() return 7 end\n")
    rc, t = run_lua(src, fuel=80000)
    assert rc == 0 and t.status == "partial" and not t.fuel_exhausted
    assert results(t, "spin") == {"": "ERROR stopped: it used its share of the fuel"}
    assert results(t, "zz") == {"": "7"}
    assert 10000 <= t.fuel_used < 80000


@lua_only
def test_lua_a_protected_call_still_catches_the_chunks_own_errors(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("caught = select(2, pcall(error, 'own', 0))\n"
                   "handled = select(2, xpcall(function() error('mine', 0) end, function(e) return 'h:' .. e end))\n"
                   "passed = select(2, xpcall(function(a, b) return a .. b end, print, 'x', 'y'))\n"
                   "counted = select(2, xpcall(function(...) return select('#', ...) end, print, 1, nil))\n"
                   "holed = select(2, xpcall(function(a, b, c) return tostring(a) .. tostring(b) .. tostring(c) end,\n"
                   "  print, nil, 2, nil))\n")
    rc, t = run_lua(src)
    values = {e["name"]: e["value"] for e in events(t, "global")}
    assert rc == 0 and t.status == "ok"
    # the wrapped xpcall hands on every extra argument, a nil hole and a trailing nil included
    assert values == {"caught": "own", "handled": "h:mine", "passed": "xy", "counted": "2", "holed": "nil2nil"}


@lua_only
def test_lua_os_exit_inside_a_protected_call_still_ends_the_chunk(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("before = 'set'\npcall(os.exit, 3)\nafter = 'went on'\n")
    rc, t = run_lua(src)
    assert rc == 0 and t.status == "ok"
    assert [e["text"] for e in events(t, "exit")] == ["3"]
    assert [e["name"] for e in events(t, "global")] == ["before"]


@lua_only
def test_lua_coroutine_resume_passes_the_fuel_stop_on(tmp_path):
    # The main thread runs a handful of instructions here, so only resume can pass the stop on.
    src = tmp_path / "artifact.bin"
    src.write_text("function resumed() local co = coroutine.create(function() while true do end end)\n"
                   "  local ok = coroutine.resume(co) return 'resumed: ' .. tostring(ok) end\n")
    rc, t = run_lua(src, fuel=80000)
    assert rc == 0 and t.status == "partial"
    assert results(t, "resumed") == {"": "ERROR stopped: it used its share of the fuel"}


@lua_only
def test_lua_the_probe_is_arg_1(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("from_arg = tostring(arg[1])\nfrom_dots = tostring(...)\nname = arg[0]\n")
    rc, t = run_lua(src, probes=[b"argprobe"])
    values = {e["name"]: e["value"] for e in events(t, "global")}
    assert rc == 0 and values == {"from_arg": "argprobe", "from_dots": "argprobe", "name": "artifact.lua"}


@lua_only
def test_lua_the_whole_budget_ends_the_run(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("".join(f"function s{i}() while true do end end\n" for i in range(9)))
    rc, t = run_lua(src, fuel=8000)
    assert rc == 0 and t.status == "partial" and t.fuel_exhausted and t.fuel_used == 8000
    called = [e["name"] for e in events(t, "call")]
    assert called[-1] == "s7" and "s8" not in called
    assert results(t, "s7") == {"": "ERROR out of fuel"}


# A finalizer runs with debug hooks off, so a __gc that spins would escape the instruction fuel and
# never return. These runs are capped in CPU seconds (RLIMIT_CPU, not wall time): a healthy run uses a
# fraction of a CPU second at any machine load; an escaped finalizer is killed by SIGXCPU and fails.
CPU_CAP = 30


def run_lua_cpu_capped(artifact: Path, runner_dir: Path | None = None, **kw):
    import resource

    def cap():
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_CAP, CPU_CAP))

    argv = plan_argv("lua", "5.4", artifact, runner_dir=runner_dir, **kw)
    r = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, preexec_fn=cap, timeout=SAFETY)
    assert r.returncode == 0, f"runner ended by signal or error {r.returncode} (a finalizer escaped the fuel?)"
    return P.parse_trace(r.stdout, "lua")


SPIN_GC = "function() while true do end end"


@lua_only
def test_lua_a_finalizer_never_runs_while_the_chunk_runs(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text(f"local mt = {{__gc = {SPIN_GC}}}\nlocal o = setmetatable({{}}, mt)\no = nil\n"
                   "for i = 1, 200000 do local t = {i} end\n"
                   "same = tostring(getmetatable(setmetatable({}, mt)) == mt)\n"
                   "kept = type(rawget(mt, '__gc'))\ndone = 'yes'\n")
    t = run_lua_cpu_capped(src, fuel=20_000_000)
    values = {e["name"]: e["value"] for e in events(t, "global")}
    assert t.status == "ok"
    assert values == {"same": "true", "kept": "function", "done": "yes"}   # the chunk still sees its metatable
    assert events(t, "refused", "__gc")


@lua_only
def test_lua_a_finalizer_left_alive_at_the_end_never_runs(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text(f"keep = setmetatable({{}}, {{__gc = {SPIN_GC}}})\ndone = 'yes'\n")
    t = run_lua_cpu_capped(src)
    assert t.status == "ok" and events(t, "global", "done")


@lua_only
def test_lua_the_runner_exits_without_closing_the_state(tmp_path):
    # The second guard on its own: a runner copy whose setmetatable guard is removed marks the object
    # for finalization; only exiting without lua_close keeps its finalizer from spinning at the end.
    text = (RUNTIME / "lua" / "trace_runner.lua").read_text()
    guard = "  env.setmetatable = function(t, mt)"
    assert text.count(guard) == 1
    runner = tmp_path / "runner"
    runner.mkdir()
    (runner / "trace_runner.lua").write_text(text.replace(guard, "  local _unused = function(t, mt)"))
    src = tmp_path / "artifact.bin"
    src.write_text(f"keep = setmetatable({{}}, {{__gc = {SPIN_GC}}})\ndone = 'yes'\n")
    t = run_lua_cpu_capped(src, runner_dir=runner)
    assert t.status == "ok" and events(t, "global", "done") and not events(t, "refused", "__gc")


@lua_only
def test_lua_text_that_does_not_compile_is_a_load_error(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("this is not lua (\n")
    rc, t = run_lua(src)
    assert rc == 0 and t.status == "error" and events(t, "error", "load")


# ========================================================================================= node
node_only = pytest.mark.needs_tool("node")


def run_node(artifact: Path, *, timeout: float = SAFETY, **kw):
    return trace_of("node", plan_argv("node", "24", artifact, **kw), timeout=timeout)


CRACK_JS = '''
var enc = %s;
var secret = enc.map(function (x) { return String.fromCharCode(x ^ 0x5a); }).join('');
function check(s) { return s === secret; }
function banner() { return 'banner:' + atob('aGVsbG8gYjY0'); }
var digest = require('crypto').createHash('md5').update('abc').digest('hex');
try { require('fs'); } catch (e) { console.error('no fs: ' + e.message); }
var rl = require('readline').createInterface({input: process.stdin});
rl.question('key? ', function (line) {
  console.log(check(line) ? 'correct' : 'wrong: ' + line);
  if (line === 'quit') process.exit(3);
});
module.exports = {check: check};
''' % json.dumps(xor(FLAG))


@node_only
def test_node_selftest_fixture_yields_the_token(tmp_path):
    rc, t = run_node(RUNTIME / "selftest" / "selftest.js", seconds=GENEROUS)
    assert rc == 0 and t.status == "ok" and TOKEN in t.strings
    assert ("check", "function/1") in t.entries and t.fuel_kind == "time"


@node_only
def test_node_reports_globals_decoded_strings_and_what_each_probe_does(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text(CRACK_JS)
    rc, t = run_node(src, seconds=GENEROUS, probes=[b"nope", FLAG.encode(), b"quit"])
    assert rc == 0 and t.status == "ok"
    assert {"kind": "global", "name": "secret", "value": FLAG} in t.events
    assert {"kind": "global", "name": "digest", "value": "900150983cd24fb0d6963f7d28e17f72"} in t.events
    assert results(t, "check") == {"probe 0": "false", "probe 1": "true", "probe 2": "false"}
    assert results(t, "exports.check")["probe 1"] == "true"
    assert results(t, "banner") == {"": "banner:hello b64"}
    assert "hello b64" in t.strings and FLAG in t.strings          # the atob result and the built global
    out = [e["text"] for e in events(t, "output") if e["stream"] == "stdout"]
    assert "wrong: nope" in out and "correct" in out and "wrong: quit" in out
    assert [e["text"] for e in events(t, "exit")] == ["3"]


@node_only
def test_node_gives_the_pure_builtins_only_and_records_every_require(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("var got = ['fs', 'child_process', 'net', 'node:http', 'os', 'vm', 'zlib', 'node:crypto']"
                   ".map(function (m) { try { require(m); return m + ':yes'; } catch (e) { return m + ':no'; } })"
                   ".join(' ');\n")
    rc, t = run_node(src, seconds=GENEROUS)
    value = [e["value"] for e in events(t, "global", "got")][0]
    assert value == "fs:no child_process:no net:no node:http:no os:no vm:no zlib:yes node:crypto:yes"
    assert [e["name"] for e in events(t, "require")] == ["fs", "child_process", "net", "node:http", "os", "vm",
                                                        "zlib", "node:crypto"]


@node_only
def test_node_a_function_that_never_returns_is_stopped_and_the_rest_is_still_traced(tmp_path):
    # Real elapsed time on purpose: spin() never returns, so vm's timeout is the expected outcome.
    src = tmp_path / "artifact.bin"
    src.write_text("function spin() { while (true) {} }\nfunction zz() { return 7; }\n")
    rc, t = run_node(src, seconds=4)
    assert rc == 0 and t.status == "partial"
    assert results(t, "spin")[""].startswith("ERROR did not finish in ")
    assert results(t, "zz") == {"": "7"}


@node_only
def test_node_the_time_budget_ends_the_run(tmp_path):
    # Real elapsed time on purpose: each call burns 300 ms of wall clock, far under its one-second
    # share, and there are many more calls than the 2 s budget holds.
    body = "function nap%d(s) { var t = Date.now(); while (Date.now() - t < 300) {} return 1; }\n"
    src = tmp_path / "artifact.bin"
    src.write_text("".join(body % i for i in range(8)))
    rc, t = run_node(src, seconds=2, probes=[b"a", b"b", b"c", b"d"])
    assert rc == 0 and t.status == "partial" and t.fuel_exhausted
    assert 1 <= len(events(t, "call")) < 32 and t.fuel_used >= 2000


@node_only
def test_node_promise_callbacks_run_inside_the_context_before_the_globals_are_read(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("var later = 'unset';\n"
                   "Promise.resolve().then(function () { later = 'set-in-a-microtask'; });\n"
                   "async function viaAwait() { await null; return 1; }\n"
                   "viaAwait().then(function () { awaited = 'after-await'; });\n")
    rc, t = run_node(src, seconds=GENEROUS)
    assert rc == 0 and t.status == "ok"
    values = {e["name"]: e["value"] for e in events(t, "global")}
    assert values["later"] == "set-in-a-microtask" and values["awaited"] == "after-await"


@node_only
def test_node_a_promise_callback_that_spins_is_stopped_by_the_calls_time_share(tmp_path):
    # Real elapsed time on purpose: the callback never ends, so the vm timeout is the expected outcome.
    # Were microtasks left to Node's own queue, it would spin after the trace and never exit (SAFETY).
    src = tmp_path / "artifact.bin"
    src.write_text("function spinLater() { Promise.resolve().then(function () { while (true) {} }); return 1; }\n"
                   "function zz() { return 7; }\n")
    rc, t = run_node(src, seconds=4)
    assert rc == 0 and t.status == "partial"
    assert results(t, "spinLater")[""].startswith("ERROR did not finish in ")
    assert results(t, "zz") == {"": "7"}


@node_only
def test_node_runs_v8_cached_data_made_by_the_same_v8_and_rejects_another(tmp_path):
    make = tmp_path / "make.js"
    make.write_text(
        "const v8 = require('v8'); const vm = require('vm'); const fs = require('fs');\n"
        "v8.setFlagsFromString('--no-lazy'); v8.setFlagsFromString('--no-flush-bytecode');\n"
        "const body = \"var k = %s.map(function (x) { return String.fromCharCode(x ^ 0x5a); }).join('');"
        " module.exports = {key: k, hello: function () { return 'from-jsc ' + k; }};\";\n"
        "const wrapped = '(function (exports, require, module, __filename, __dirname) {' + body + '\\n})';\n"
        "fs.writeFileSync(process.argv[2], new vm.Script(wrapped).createCachedData());\n" % json.dumps(xor(FLAG)))
    jsc = tmp_path / "artifact.jsc"
    subprocess.run(["node", str(make), str(jsc)], check=True)
    assert P.classify(jsc.read_bytes(), jsc.name).kind == "jsc"
    rc, t = run_node(jsc, seconds=GENEROUS)
    assert rc == 0 and t.status == "ok"
    assert {"kind": "global", "name": "exports.key", "value": FLAG} in t.events
    assert results(t, "exports.hello") == {"": "from-jsc " + FLAG}
    blob = bytearray(jsc.read_bytes())
    blob[4] ^= 0xFF                                        # another V8's version hash
    other = tmp_path / "other.jsc"
    other.write_bytes(bytes(blob))
    rc, t = run_node(other, seconds=GENEROUS)
    assert rc == 0 and t.status == "error" and events(t, "call") == []
    assert "V8 rejected the cached data" in events(t, "error", "load")[0]["text"]


@node_only
def test_node_es_module_syntax_is_a_named_load_error(tmp_path):
    src = tmp_path / "artifact.bin"
    src.write_text("import fs from 'fs';\nexport const x = 1;\n")
    rc, t = run_node(src, seconds=GENEROUS)
    assert rc == 0 and t.status == "error"
    assert "ES module syntax is not run" in events(t, "error", "load")[0]["text"]


# ========================================================================================== jvm
jvm_only = pytest.mark.needs_tool("javac", "java")

JAVA = {
    "Crack": '''
import java.util.Scanner;
public class Crack {
    static final byte[] ENC = {%s};
    static String KEY;
    static int COUNT = 7;
    static {
        StringBuilder b = new StringBuilder();
        for (byte x : ENC) b.append((char) (x ^ 0x5a));
        KEY = b.toString();
    }
    public static boolean check(String s) { return KEY.equals(s); }
    static String banner() { return "banner-" + COUNT; }
    static byte[] raw() { return new byte[] {(byte) 0xff, 0x00}; }
    public static void main(String[] a) {
        Scanner in = new Scanner(System.in);
        String line = in.hasNextLine() ? in.nextLine() : "";
        System.out.println(check(line) ? "correct" : "wrong: " + line + " argv=" + a[0]);
    }
}''' % ", ".join(str(b) for b in xor(FLAG)),
    "Spin": '''
public class Spin {
    static int n;
    public static int spin() { while (true) { n++; } }
    public static int zz() { return 7; }
}''',
    "Exit": '''
public class Exit {
    public static void main(String[] a) { System.out.println("bye"); System.exit(3); }
}''',
    "Naps": "public class Naps {\n" + "".join(
        "    public static int nap%d(String s) throws Exception { Thread.sleep(400); return 1; }\n" % i
        for i in range(12)) + "}",
    "Uses": 'public class Uses { public static String joined() { return "uses-" + Helper.word(); } }',
    "Arrays": '''
public class Arrays {
    public static String hexOf(byte[] b) {
        StringBuilder s = new StringBuilder("bytes:");
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
    public static int countChars(char[] c) { return c.length; }
    public static int twoArgs(String a, String b) { return 1; }
}''',
    "Helper": 'public class Helper { public static String word() { return "helper"; } }',
    "Boom": '''
public class Boom {
    static { if (true) throw new IllegalStateException("clinit says no"); }
    public static int never() { return 1; }
}''',
}


@pytest.fixture(scope="module")
def jvm(tmp_path_factory):
    root = tmp_path_factory.mktemp("jvm")
    (root / "run").mkdir()
    subprocess.run(["javac", "-nowarn", "-d", str(root / "run"), str(RUNTIME / "jvm" / "TraceRunner.java")],
                   check=True, capture_output=True)
    (root / "src").mkdir()
    for name, text in JAVA.items():
        (root / "src" / f"{name}.java").write_text(text)
    shutil.copy(RUNTIME / "selftest" / "Selftest.java", root / "src" / "Selftest.java")
    subprocess.run(["javac", "-nowarn", "-d", str(root / "cls"), *sorted(str(p) for p in (root / "src").glob("*.java"))],
                   check=True, capture_output=True)
    return root


def run_jvm(root: Path, artifact: Path, deps: Path | None = None, **kw):
    kw.setdefault("seconds", GENEROUS)
    return trace_of("jvm", plan_argv("jvm", "", artifact, deps, runner_dir=root / "run", **kw))


@jvm_only
def test_jvm_selftest_fixture_yields_the_token(jvm):
    rc, t = run_jvm(jvm, jvm / "cls" / "Selftest.class")
    assert rc == 0 and t.status == "ok" and TOKEN in t.strings and t.fuel_kind == "time"
    assert ("Selftest.check", "static boolean (String)") in t.entries


@jvm_only
def test_jvm_reports_what_the_static_initialiser_built_and_what_each_probe_does(jvm):
    rc, t = run_jvm(jvm, jvm / "cls" / "Crack.class", probes=[b"nope", FLAG.encode()])
    assert rc == 0 and t.status == "ok"
    assert {"kind": "static", "name": "Crack.KEY", "value": FLAG} in t.events
    assert {"kind": "static", "name": "Crack.COUNT", "value": "7"} in t.events
    assert [e["value"] for e in events(t, "static", "Crack.ENC")][0].startswith("hex:")
    assert results(t, "Crack.check") == {"probe 0": "false", "probe 1": "true"}
    assert results(t, "Crack.banner") == {"": "banner-7"}
    assert results(t, "Crack.raw") == {"": "hex:ff00"}
    out = [e["text"] for e in events(t, "output")]
    assert out == ["wrong: nope argv=nope\n", "correct\n"]
    assert FLAG in t.strings and "banner-7" in t.strings


@jvm_only
def test_jvm_a_jar_is_read_from_memory_with_its_main_class_first(jvm, tmp_path):
    jar = tmp_path / "artifact.bin"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: Uses\n")
        for name in ("Helper", "Uses"):
            z.write(jvm / "cls" / f"{name}.class", f"{name}.class")
    assert P.classify(jar.read_bytes(), "app.jar").kind == "jar"
    rc, t = run_jvm(jvm, jar)
    assert rc == 0 and t.status == "ok"
    assert [n for n, _ in t.entries] == ["Uses.joined", "Helper.word"]
    assert results(t, "Uses.joined") == {"": "uses-helper"}


@jvm_only
def test_jvm_a_class_needs_its_dependencies_and_takes_them_from_the_deps_folder(jvm, tmp_path):
    rc, t = run_jvm(jvm, jvm / "cls" / "Uses.class")
    assert t.status == "partial" and "NoClassDefFoundError" in results(t, "Uses.joined")[""]
    deps = tmp_path / "dep"
    deps.mkdir()
    shutil.copy(jvm / "cls" / "Helper.class", deps / "000.bin")
    rc, t = run_jvm(jvm, jvm / "cls" / "Uses.class", deps)
    assert rc == 0 and t.status == "ok" and results(t, "Uses.joined") == {"": "uses-helper"}
    assert [n for n, _ in t.entries] == ["Uses.joined"]        # a dependency is loaded, not traced


@jvm_only
def test_jvm_a_static_initialiser_that_throws_is_reported_and_its_methods_are_not_called(jvm):
    rc, t = run_jvm(jvm, jvm / "cls" / "Boom.class")
    assert rc == 0 and t.status == "partial"
    assert events(t, "error", "Boom.<clinit>")[0]["text"] == "java.lang.IllegalStateException: clinit says no"
    assert t.errors() == ["Boom.<clinit>: java.lang.IllegalStateException: clinit says no"]
    assert events(t, "call") == [] and events(t, "static") == []


@jvm_only
def test_jvm_methods_taking_bytes_or_chars_get_each_probe(jvm):
    rc, t = run_jvm(jvm, jvm / "cls" / "Arrays.class", probes=[b"AB", b"xyz"])
    assert rc == 0 and t.status == "ok"
    assert results(t, "Arrays.hexOf") == {"probe 0": "bytes:4142", "probe 1": "bytes:78797a"}
    assert results(t, "Arrays.countChars") == {"probe 0": "2", "probe 1": "3"}
    assert results(t, "Arrays.twoArgs") == {}                      # listed, not called


@jvm_only
def test_jvm_system_exit_still_gives_the_trace(jvm):
    rc, t = run_jvm(jvm, jvm / "cls" / "Exit.class")
    assert rc == 3 and t.status == "partial"
    assert t.notes == ("the artifact ended the JVM (System.exit) before the trace was complete",)
    assert [e["text"] for e in events(t, "output")] == ["bye\n"]


@jvm_only
def test_jvm_bytes_that_are_no_class_are_a_load_error(jvm, tmp_path):
    bad = tmp_path / "artifact.bin"
    bad.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34 definitely not a class")
    rc, t = run_jvm(jvm, bad)
    assert rc == 0 and t.status == "error" and t.entries == ()


@jvm_only
def test_jvm_a_method_that_never_returns_is_left_behind_and_the_rest_is_still_traced(jvm):
    # Real elapsed time on purpose: spin() never returns, so its one-second share is the expected outcome.
    rc, t = run_jvm(jvm, jvm / "cls" / "Spin.class", seconds=8)
    assert rc == 0 and t.status == "partial" and not t.fuel_exhausted
    assert results(t, "Spin.spin") == {"": "ERROR did not return in 1000 ms"}
    assert results(t, "Spin.zz") == {"": "7"}


@jvm_only
def test_jvm_the_time_budget_ends_the_run(jvm):
    # Real elapsed time on purpose: 96 calls of 400 ms each (well under the one-second share) cannot
    # fit in 8 s, so the watchdog is the expected outcome.
    rc, t = run_jvm(jvm, jvm / "cls" / "Naps.class", seconds=8, probes=[b"p"] * 8)
    assert rc == 0 and t.status == "partial" and t.fuel_exhausted and t.fuel_limit == 8000
    assert "the run reached its time limit of 8000 ms" in t.notes
    assert 1 <= len(events(t, "call")) < 96


# ======================================================================================= dotnet
dotnet_only = pytest.mark.needs_tool("dotnet")

CSHARP = {
    "Crack": ("exe", '''
using System;
using System.Text;
public static class Crack
{
    static readonly byte[] Enc = { %s };
    static string Key;
    static int Count = 7;
    static Crack()
    {
        var b = new StringBuilder();
        foreach (byte x in Enc) b.Append((char)(x ^ 0x5a));
        Key = b.ToString();
    }
    public static bool Check(string s) { return Key == s; }
    static string Banner() { return "banner-" + Count; }
    public static int Main(string[] a)
    {
        string line = Console.ReadLine() ?? "";
        Console.WriteLine(Check(line) ? "correct" : "wrong: " + line + " argv=" + a[0]);
        return 0;
    }
}''' % ", ".join(str(b) for b in xor(FLAG))),
    "Spin": ("library", '''
public static class Spin
{
    static int n;
    public static int Loop() { while (true) { n++; } }
    public static int Zz() { return 7; }
}'''),
    "Exit": ("exe", '''
public static class Exit
{
    public static void Main(string[] a) { System.Console.WriteLine("bye"); System.Environment.Exit(3); }
}'''),
    "Naps": ("library", "public static class Naps {\n" + "".join(
        "    public static int Nap%d(string s) { System.Threading.Thread.Sleep(400); return 1; }\n" % i
        for i in range(12)) + "}"),
    "Boom": ("library", '''
public static class Boom
{
    static Boom() { throw new System.InvalidOperationException("cctor says no"); }
    public static int Never() { return 1; }
}'''),
    "Arrays": ("library", '''
public static class Arrays
{
    public static string HexOf(byte[] b) { return "bytes:" + System.Convert.ToHexString(b).ToLowerInvariant(); }
    public static int CountChars(char[] c) { return c.Length; }
}'''),
}
# A library and an assembly that references it, compiled into a folder of their own (an assembly
# beside TraceRunner.dll would be found by the host's own probing, not through --deps).
CS_HELPER = 'public static class Helper { public static string Word() { return "helper"; } }'
CS_USES = 'public static class Uses { public static string Joined() { return "uses-" + Helper.Word(); } }'


@pytest.fixture(scope="module")
def dotnet(tmp_path_factory):
    """The runner and the fixtures compiled with the SDK's own csc (no project, no restore, no network)."""
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
    sdks = re.findall(r"^(\S+) \[(.+)\]$", subprocess.run(["dotnet", "--list-sdks"], capture_output=True,
                                                         text=True, env=env).stdout, re.M)
    if not sdks:
        pytest.skip("no .NET SDK is installed (dotnet --list-sdks is empty): the runner cannot be compiled")
    version, base = sdks[-1]
    csc = Path(base) / version / "Roslyn" / "bincore" / "csc.dll"
    refs = sorted((Path(base).parent / "packs" / "Microsoft.NETCore.App.Ref").glob("*/ref/net*"))
    if not csc.is_file() or not refs:
        pytest.skip("the .NET SDK has no Roslyn csc or no reference pack: the runner cannot be compiled")
    refdir = refs[-1]
    root = tmp_path_factory.mktemp("dotnet")

    def compile_cs(src: Path, out: Path, target: str) -> None:
        r = subprocess.run(["dotnet", str(csc), "-nologo", f"-target:{target}", f"-out:{out}",
                            *[f"-r:{p}" for p in sorted(refdir.glob("*.dll"))], str(src)],
                           capture_output=True, text=True, env=env)
        assert r.returncode == 0, r.stdout + r.stderr

    compile_cs(RUNTIME / "dotnet" / "TraceRunner.cs", root / "TraceRunner.dll", "exe")
    (root / "TraceRunner.runtimeconfig.json").write_text(json.dumps({"runtimeOptions": {
        "tfm": refdir.name, "framework": {"name": "Microsoft.NETCore.App", "version": refdir.parent.parent.name}}}))
    for name, (target, text) in CSHARP.items():
        (root / f"{name}.cs").write_text(text)
        compile_cs(root / f"{name}.cs", root / f"{name}.dll", target)
    compile_cs(RUNTIME / "selftest" / "Selftest.cs", root / "Selftest.dll", "library")
    apart = root / "apart"
    apart.mkdir()
    (apart / "Helper.cs").write_text(CS_HELPER)
    (apart / "Uses.cs").write_text(CS_USES)
    compile_cs(apart / "Helper.cs", apart / "Helper.dll", "library")
    r = subprocess.run(["dotnet", str(csc), "-nologo", "-target:library", f"-out:{apart / 'Uses.dll'}",
                        f"-r:{apart / 'Helper.dll'}", *[f"-r:{p}" for p in sorted(refdir.glob("*.dll"))],
                        str(apart / "Uses.cs")], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return root, env


def run_dotnet(fx, artifact: Path, deps: Path | None = None, **kw):
    root, env = fx
    kw.setdefault("seconds", GENEROUS)
    # `dotnet /opt/runner/TraceRunner.dll` as the plan says: the runtimeconfig beside the dll is read
    return trace_of("dotnet", plan_argv("dotnet", "", artifact, deps, runner_dir=root, **kw), env=env)


@dotnet_only
def test_dotnet_fixture_assemblies_are_what_classify_calls_cil(dotnet):
    root, _ = dotnet
    assert P.classify((root / "Crack.dll").read_bytes(), "Crack.dll").kind == "assembly"
    assert P.classify((root / "Selftest.dll").read_bytes(), "x").runtime == "dotnet"


@dotnet_only
def test_dotnet_selftest_fixture_yields_the_token(dotnet):
    rc, t = run_dotnet(dotnet, dotnet[0] / "Selftest.dll")
    assert rc == 0 and t.status == "ok" and TOKEN in t.strings and t.fuel_kind == "time"
    assert ("Selftest.Check", "static Boolean (String)") in t.entries


@dotnet_only
def test_dotnet_reports_what_the_static_constructor_built_and_what_each_probe_does(dotnet):
    rc, t = run_dotnet(dotnet, dotnet[0] / "Crack.dll", probes=[b"nope", FLAG.encode()])
    assert rc == 0 and t.status == "ok"
    assert {"kind": "static", "name": "Crack.Key", "value": FLAG} in t.events
    assert {"kind": "static", "name": "Crack.Count", "value": "7"} in t.events
    assert results(t, "Crack.Check") == {"probe 0": "False", "probe 1": "True"}
    assert results(t, "Crack.Banner") == {"": "banner-7"}
    assert results(t, "Crack.Main") == {"probe 0": "0", "probe 1": "0"}
    assert [e["text"] for e in events(t, "output")] == ["wrong: nope argv=nope\n", "correct\n"]
    assert FLAG in t.strings


@dotnet_only
def test_dotnet_a_static_constructor_that_throws_is_reported(dotnet):
    rc, t = run_dotnet(dotnet, dotnet[0] / "Boom.dll")
    assert rc == 0 and t.status == "partial"
    assert t.errors() == ["Boom..cctor: System.InvalidOperationException: cctor says no"]
    assert events(t, "call") == [] and events(t, "static") == []


@dotnet_only
def test_dotnet_methods_taking_bytes_or_chars_get_each_probe(dotnet):
    rc, t = run_dotnet(dotnet, dotnet[0] / "Arrays.dll", probes=[b"AB", b"xyz"])
    assert rc == 0 and t.status == "ok"
    assert results(t, "Arrays.HexOf") == {"probe 0": "bytes:4142", "probe 1": "bytes:78797a"}
    assert results(t, "Arrays.CountChars") == {"probe 0": "2", "probe 1": "3"}


@dotnet_only
def test_dotnet_a_referenced_assembly_is_resolved_from_the_deps_folder(dotnet, tmp_path):
    apart = dotnet[0] / "apart"
    rc, t = run_dotnet(dotnet, apart / "Uses.dll")
    assert t.status == "partial" and "Helper" in results(t, "Uses.Joined")[""]
    assert results(t, "Uses.Joined")[""].startswith("ERROR ")
    deps = tmp_path / "dep"
    deps.mkdir()
    shutil.copy(apart / "Helper.dll", deps / "000.bin")
    (deps / "001.bin").write_bytes(b"not an assembly")
    rc, t = run_dotnet(dotnet, apart / "Uses.dll", deps)
    assert rc == 0 and t.status == "ok" and results(t, "Uses.Joined") == {"": "uses-helper"}
    assert [n for n, _ in t.entries] == ["Uses.Joined"]          # a dependency is loaded, not traced


@dotnet_only
def test_dotnet_environment_exit_still_gives_the_trace(dotnet):
    rc, t = run_dotnet(dotnet, dotnet[0] / "Exit.dll")
    assert rc == 3 and t.status == "partial"
    assert t.notes == ("the artifact ended the process (Environment.Exit) before the trace was complete",)
    assert [e["text"] for e in events(t, "output")] == ["bye\n"]


@dotnet_only
def test_dotnet_bytes_that_are_no_assembly_are_a_load_error(dotnet, tmp_path):
    bad = tmp_path / "artifact.bin"
    bad.write_bytes(b"MZ definitely not an assembly")
    rc, t = run_dotnet(dotnet, bad)
    assert rc == 0 and t.status == "error" and t.entries == () and events(t, "error", "load")


@dotnet_only
def test_dotnet_a_method_that_never_returns_is_left_behind_and_the_rest_is_still_traced(dotnet):
    # Real elapsed time on purpose: Loop() never returns, so its one-second share is the expected outcome.
    rc, t = run_dotnet(dotnet, dotnet[0] / "Spin.dll", seconds=8)
    assert rc == 0 and t.status == "partial" and not t.fuel_exhausted
    assert results(t, "Spin.Loop") == {"": "ERROR did not return in 1000 ms"}
    assert results(t, "Spin.Zz") == {"": "7"}


@dotnet_only
def test_dotnet_the_time_budget_ends_the_run(dotnet):
    # Real elapsed time on purpose: 96 calls of 400 ms each (well under the one-second share) cannot
    # fit in 8 s, so the watchdog is the expected outcome.
    rc, t = run_dotnet(dotnet, dotnet[0] / "Naps.dll", seconds=8, probes=[b"p"] * 8)
    assert rc == 0 and t.status == "partial" and t.fuel_exhausted and t.fuel_limit == 8000
    assert "the run reached its time limit of 8000 ms" in t.notes
    assert 1 <= len(events(t, "call")) < 96


# ================================================================================= entry script
entry_only = pytest.mark.needs_tool("bash", "tar", "timeout")
ENTRY = RUNTIME / "entry.sh"


def entry(tmp: Path, args: list[str], stdin: bytes):
    work = tmp / "work"
    work.mkdir(exist_ok=True)
    env = dict(os.environ, CTF_RUNTIME_WORK=str(work))
    try:
        r = subprocess.run(["bash", str(ENTRY), *args], input=stdin, capture_output=True, env=env, timeout=SAFETY)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"entry.sh did not end within {SAFETY} s") from None
    return r, work


def request(members) -> bytes:
    sandbox = importlib.import_module("sandbox")
    try:
        return sandbox.runtime_request(members)
    finally:
        sys.modules.pop("sandbox", None)


@entry_only
def test_entry_unpacks_the_request_and_runs_the_command_in_the_work_folder(tmp_path):
    r, work = entry(tmp_path, ["30", "cat", "artifact.bin", "dep/000.bin"],
                    request([("artifact.bin", b"ART-"), ("dep/000.bin", b"DEP")]))
    assert (r.returncode, r.stdout) == (0, b"ART-DEP")
    assert sorted(p.name for p in work.iterdir()) == ["artifact.bin", "dep"]


@entry_only
def test_entry_unpacks_only_the_two_request_paths(tmp_path):
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body in (("artifact.bin", b"A"), ("evil.sh", b"#!/bin/sh\n"), ("dep/000.bin", b"D")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    r, work = entry(tmp_path, ["30", "true"], buf.getvalue())
    assert r.returncode == 0
    assert sorted(p.relative_to(work).as_posix() for p in work.rglob("*")) == ["artifact.bin", "dep", "dep/000.bin"]


@entry_only
def test_entry_gives_the_runner_no_stdin_and_passes_its_exit_status(tmp_path):
    r, _ = entry(tmp_path, ["30", "sh", "-c", "cat; echo out; echo err >&2; exit 3"], request([("artifact.bin", b"A")]))
    assert (r.returncode, r.stdout, r.stderr) == (3, b"out\n", b"err\n")


@entry_only
def test_entry_stops_a_runner_at_the_time_limit_with_status_124(tmp_path):
    # Real elapsed time on purpose: the command sleeps far longer than the one-second limit.
    r, _ = entry(tmp_path, ["1", "sleep", "300"], request([("artifact.bin", b"A")]))
    assert r.returncode == 124


@entry_only
def test_entry_kills_a_runner_that_ignores_the_stop_two_seconds_later(tmp_path):
    # Real elapsed time on purpose: the command ignores TERM and sleeps far past the one-second
    # limit; only the KILL that follows ends it, and timeout(1) then exits 128 + 9.
    r, _ = entry(tmp_path, ["1", "sh", "-c", "trap '' TERM; sleep 120; echo late"], request([("artifact.bin", b"A")]))
    assert r.returncode == 137 and b"late" not in r.stdout


@entry_only
def test_entry_cuts_the_runners_output_at_its_caps(tmp_path):
    big = f"import sys; sys.stdout.write('x' * {9 << 20}); sys.stderr.write('e' * {1 << 20})"
    r, _ = entry(tmp_path, ["60", sys.executable, "-I", "-c", big], request([("artifact.bin", b"A")]))
    assert len(r.stdout) == 8 << 20 and len(r.stderr) <= 256 << 10


@entry_only
@pytest.mark.parametrize("args", [[], ["30"], ["soon", "true"], ["", "true"], ["3;id", "true"]])
def test_entry_refuses_a_bad_command_line_before_reading_anything(tmp_path, args):
    r, work = entry(tmp_path, args, request([("artifact.bin", b"A")]))
    assert r.returncode == 2 and r.stdout == b"" and list(work.iterdir()) == []


@entry_only
def test_entry_fails_when_the_request_is_not_a_tar(tmp_path):
    r, _ = entry(tmp_path, ["30", "echo", "ran"], b"not a tar")
    assert r.returncode != 0 and b"ran" not in r.stdout
