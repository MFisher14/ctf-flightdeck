#!/usr/bin/env python3
"""B-241: the isolated unpack worker (solvers/binary/unpack_worker.py).

The packed images are synthetic PE32 files from the B-241 builder (``tests/test_b241_pe32.py``): a stub
that decrypts bytes in a writable+executable section and jumps to them.  The worker is a real child
process in every process test.  Under the suite's own sandbox the OS sandbox cannot be nested, so those
tests start the child through a pass-through prefix (the child's own limits and audit hook still apply)
and the one test of the real OS sandbox skips with the probe's reason: NOT RUN there, never green.
"""
from __future__ import annotations

import json
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for extra in (ROOT, ROOT / "tests"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from solvers.binary import unpack_worker as W  # noqa: E402
from solvers.common import native_emulate as NE  # noqa: E402
from solvers.toolkits import pe_emu as PE  # noqa: E402
from test_b241_pe32 import PACKED_PLAIN, L, build_pe32  # noqa: E402

engine = pytest.mark.needs_tool("py:unicorn", "py:capstone")
WORKER = ROOT / "solvers" / "binary" / "unpack_worker.py"
# Starts whatever follows it, with no containment of its own: stands in for the OS sandbox prefix.
PASS_THROUGH = (sys.executable, "-I", "-c", "import os, sys; os.execv(sys.argv[1], sys.argv[1:])")
# The process tests bound work by instructions; the wait is generous because the machine runs at a load of
# 50-170 and no test asserts an upper bound on elapsed time.
WAIT = 540.0


def need_engine():
    if not NE.UNICORN_AVAILABLE:
        pytest.skip(f"real Unicorn backend unavailable: {NE.UNICORN_UNAVAILABLE_REASON}")


def packed(**kwargs):
    return build_pe32(entry=0x1000 + L["m_stub"], **kwargs)


def fake_worker(body: str):
    """A stand-in child that ignores the worker command line and runs ``body``."""
    return (sys.executable, "-I", "-c", body)


# ------------------------------------------------------------------ the child process, end to end
@engine
def test_the_child_recovers_the_payload_and_dumps_a_loadable_pe():
    need_engine()
    outcome = W.unpack(packed(), sandbox=PASS_THROUGH, timeout=WAIT)
    assert outcome.status == "unpacked" and outcome.reason == "" and outcome.oep_rva == 0x4000
    dumped = PE.map_pe(outcome.dump)
    assert dumped.entry_rva == 0x4000 and dumped.rva_bytes(0x4000, 6) == PACKED_PLAIN
    report = outcome.report
    assert [layer["oep_rva"] for layer in report["layers"]] == [0x4000]
    assert report["layers"][0]["written_bytes"] == 6
    # the unpacked code then ran to its own return: there was no second layer
    assert report["notes"] == ["after layer 1: the image ran to its return without executing bytes it wrote"]
    assert report["image"]["sections"] == [".text", ".idata", ".data", ".pack"] and report["image"]["is_64"] is False
    # the child's kernel limits were set, by name
    assert report["limits"]["cpu_seconds"] == W.DEFAULT_CPU and report["limits"]["file_size"] == 0
    assert report["limits"]["core"] == 0 and report["limits"]["open_files"] == 64
    # the child installed its audit hook before it ran the image, and checked that it refuses
    assert report["guard"] == {"write": "denied", "connect": "denied", "spawn": "denied"}


@engine
def test_the_child_reports_not_packed_and_declines_by_name():
    need_engine()
    plain = W.unpack(build_pe32(entry=0x1000 + L["teb_self"]), sandbox=PASS_THROUGH, timeout=WAIT)
    assert plain.status == "not-packed" and plain.dump == b"" and plain.oep_rva is None
    assert plain.reason == "the image ran to its return without executing bytes it wrote"
    names = ("VirtualAlloc", "SetLastError", "GetLastError", "CreateFileA")
    denied = W.unpack(build_pe32(("kernel32.dll", names), entry=0x1000 + L["m_denied"]),
                      sandbox=PASS_THROUGH, timeout=WAIT)
    assert denied.status == "declined" and "kernel32.dll!CreateFileA" in denied.reason and denied.dump == b""
    junk = W.unpack(b"MZ" + bytes(200), sandbox=PASS_THROUGH, timeout=WAIT)
    assert junk.status == "declined" and junk.reason.startswith("not a PE image the mapper takes")
    spin = bytearray(build_pe32())
    spin[0x200:0x202] = b"\xeb\xfe"                                        # the entry point: jmp to itself
    looped = W.unpack(bytes(spin), sandbox=PASS_THROUGH, timeout=WAIT, instruction_cap=500)
    assert looped.status == "declined" and "instruction budget exceeded" in looped.reason


def two_layer_image() -> bytes:
    """Stub 1 (in .text) decrypts stub 2 at .pack+0 and jumps to it; stub 2 decrypts the payload at
    .pack+0x20 and jumps to it.  Both stubs are the listing's m_stub with other immediates."""
    raw = bytearray(build_pe32(entry=0x1000 + L["m_stub"]))
    stub1 = 0x200 + L["m_stub"]
    stub = bytes(raw[stub1:stub1 + 24])
    # mov esi, imm32 ; mov ecx, imm32 ; xor byte [esi], 0x5A ; inc esi ; dec ecx ; jnz ; mov eax, imm32 ; jmp eax
    assert (stub[:1], stub[5:6], stub[17:18], stub[22:]) == (b"\xbe", b"\xb9", b"\xb8", b"\xff\xe0")
    raw[stub1 + 6:stub1 + 10] = (24).to_bytes(4, "little")                # stub 1 decrypts stub 2's 24 bytes
    inner = 0x404020
    stub2 = stub[:1] + inner.to_bytes(4, "little") + stub[5:18] + inner.to_bytes(4, "little") + stub[22:]
    raw[0x1000:0x1000 + 24] = bytes(b ^ 0x5A for b in stub2)
    raw[0x1020:0x1026] = bytes(b ^ 0x5A for b in PACKED_PLAIN)
    return bytes(raw)


@engine
def test_layers_are_followed_and_the_deepest_dump_is_returned():
    need_engine()
    kwargs = dict(instruction_cap=5_000, memory_cap=50_000, wall_seconds=60.0)
    report, dump = W.unpack_image(two_layer_image(), layers=4, **kwargs)
    assert report["status"] == "unpacked" and [layer["oep_rva"] for layer in report["layers"]] == [0x4000, 0x4020]
    assert report["oep_rva"] == 0x4020 and report["dump_size"] == len(dump)
    deepest = PE.map_pe(dump)
    assert deepest.entry_rva == 0x4020 and deepest.rva_bytes(0x4020, 6) == PACKED_PLAIN
    assert [layer["written_bytes"] for layer in report["layers"]] == [24, 6]   # each layer counts its own writes
    # one layer asked for: the first hand-over is where it stops, with the inner payload still encrypted
    report, dump = W.unpack_image(two_layer_image(), layers=1, **kwargs)
    assert [layer["oep_rva"] for layer in report["layers"]] == [0x4000] and report["notes"] == []
    assert PE.map_pe(dump).rva_bytes(0x4020, 6) == bytes(b ^ 0x5A for b in PACKED_PLAIN)
    with pytest.raises(ValueError, match="layers must be"):
        W.unpack(b"", layers=0, sandbox=PASS_THROUGH)


# ------------------------------------------------------------------ containment
def run_probe(tmp_path, prefix, *flags):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    try:
        port = listener.getsockname()[1]
        done = subprocess.run([*prefix, sys.executable, "-I", "-B", str(WORKER), "--probe", str(port), *flags],
                              capture_output=True, text=True, cwd=str(tmp_path), timeout=WAIT)
    finally:
        listener.close()
    assert done.returncode == 0, done.stderr[-500:]
    return json.loads(done.stdout)


def test_the_audit_hook_refuses_writes_sockets_and_children(tmp_path):
    hooked = run_probe(tmp_path, ())
    assert hooked == {"connect": "denied: PermissionError", "spawn": "denied: PermissionError",
                      "write": "denied: PermissionError"}
    assert not (tmp_path / "probe.txt").exists()
    # the control: without the hook (and with no OS sandbox around it) the same three attempts succeed, so
    # the denials above are the hook's doing
    bare = run_probe(tmp_path, (), "--no-hook")
    assert bare == {"connect": "allowed", "spawn": "allowed", "write": "allowed"}
    assert (tmp_path / "probe.txt").read_text() == "x"


GUARD_CHECK = ("import json, sys; sys.path.insert(0, %r)\n"
               "from solvers.binary import unpack_worker as W\n"
               "before = W.guard_state()\n"
               "W.install_guard()\n"
               "print(json.dumps([before, W.guard_state()]))\n" % str(ROOT))


def test_guard_state_reads_the_hook_without_acting():
    """guard_state asks the hook with sys.audit alone: allowed before install_guard, denied after."""
    done = subprocess.run([sys.executable, "-I", "-B", "-c", GUARD_CHECK], capture_output=True, text=True,
                          timeout=WAIT)
    assert done.returncode == 0, done.stderr[-500:]
    before, after = json.loads(done.stdout)
    assert before == {"write": "allowed", "connect": "allowed", "spawn": "allowed"}
    assert after == {"write": "denied", "connect": "denied", "spawn": "denied"}


def test_a_worker_whose_hook_is_not_active_refuses_to_run(tmp_path):
    """The real child, with install_guard made a no-op: it must not run the image."""
    shim = tmp_path / "shim.py"
    shim.write_text("import runpy, sys\n"
                    "sys.path.insert(0, %r)\n"
                    "from solvers.binary import unpack_worker as W\n"
                    "W.install_guard = lambda: None\n"
                    "raise SystemExit(W.main(['--worker']))\n" % str(ROOT), encoding="utf-8")
    # the shim stands in for the sandbox prefix and ignores the worker command line that follows it
    outcome = W.unpack(b"MZ", sandbox=(sys.executable, "-I", "-B", str(shim)), timeout=WAIT)
    assert outcome.status == "declined" and "the audit hook is not refusing" in outcome.reason


def test_the_os_sandbox_contains_the_child_on_its_own(tmp_path):
    prefix, why = W.os_sandbox(refresh=True)
    if prefix is None:
        pytest.skip(f"OS sandbox unavailable here: {why}")
    seen = run_probe(tmp_path, prefix, "--no-hook")
    assert seen["connect"].startswith("denied")                           # every platform: no network
    if sys.platform == "darwin":
        assert seen["write"].startswith("denied") and seen["spawn"].startswith("denied")
        assert not (tmp_path / "probe.txt").exists()


@engine
def test_an_unpack_under_the_os_sandbox_recovers_the_payload():
    need_engine()
    prefix, why = W.os_sandbox(refresh=True)
    if prefix is None:
        pytest.skip(f"OS sandbox unavailable here: {why}")
    outcome = W.unpack(packed(), timeout=WAIT)                             # the default: under the OS sandbox
    assert outcome.status == "unpacked" and PE.map_pe(outcome.dump).rva_bytes(0x4000, 6) == PACKED_PLAIN
    assert outcome.report["guard"] == {"write": "denied", "connect": "denied", "spawn": "denied"}


def test_no_os_sandbox_means_no_run(monkeypatch, tmp_path):
    monkeypatch.setattr(W, "_candidate", lambda: (("/usr/bin/false",), "a sandbox that refuses"))
    monkeypatch.setattr(W, "_PROBE", {})
    assert W.os_sandbox() == (None, "a sandbox that refuses probe exited 1")
    with pytest.raises(W.SandboxUnavailable, match="a sandbox that refuses probe exited 1"):
        W.unpack(packed())
    monkeypatch.setattr(W, "_candidate", lambda: (None, "no OS sandbox is known for plan9"))
    monkeypatch.setattr(W, "_PROBE", {})
    with pytest.raises(W.SandboxUnavailable, match="plan9"):
        W.unpack(packed())
    # the CLI says so and exits 2
    sample = tmp_path / "sample.exe"
    sample.write_bytes(packed())
    assert W.main([str(sample)]) == 2


def test_kernel_limits_apply_in_a_child():
    code = ("import sys; sys.path.insert(0, %r)\n"
            "from solvers.binary import unpack_worker as W\n"
            "import resource, json\n"
            "applied = W.apply_limits(1)\n"
            "print(json.dumps([applied, resource.getrlimit(resource.RLIMIT_CPU)[0], "
            "resource.getrlimit(resource.RLIMIT_FSIZE)[0], resource.getrlimit(resource.RLIMIT_CORE)[0]]), flush=True)\n"
            "while True: pass\n" % str(ROOT))
    done = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True, timeout=WAIT)
    applied, cpu, fsize, core = json.loads(done.stdout.splitlines()[0])
    assert applied == {"cpu_seconds": 1, "file_size": 0, "core": 0, "open_files": 64}
    assert (cpu, fsize, core) == (1, 0, 0)
    assert done.returncode == -signal.SIGXCPU                              # the kernel stopped the busy loop


# ------------------------------------------------------------------ what the parent makes of a bad child
def test_a_child_stopped_by_its_cpu_limit_is_a_named_decline():
    killed = fake_worker("import os, signal; os.kill(os.getpid(), signal.SIGXCPU)")
    outcome = W.unpack(b"x", sandbox=killed, timeout=WAIT, cpu_seconds=7)
    assert outcome.status == "declined" and "SIGXCPU" in outcome.reason and "CPU limit of 7 s" in outcome.reason
    failed = fake_worker("import sys; sys.stderr.write('first line\\nboom: the reason\\n'); sys.exit(3)")
    outcome = W.unpack(b"x", sandbox=failed, timeout=WAIT)
    assert outcome.status == "declined" and outcome.reason == "the worker exited 3: boom: the reason"


def test_a_child_that_does_not_finish_is_killed_at_the_timeout():
    began = time.monotonic()
    outcome = W.unpack(b"x", sandbox=fake_worker("import time; time.sleep(3600)"), timeout=0.5)
    assert outcome.status == "declined" and "did not finish within 0.5 s" in outcome.reason
    assert time.monotonic() - began >= 0.5                                 # a lower bound only


@pytest.mark.parametrize("body,reason", [
    ("print('not json')", "not the report"),
    ("import json; print(json.dumps({'status': 'unpacked', 'dump_size': 0}))", "inconsistent"),
    ("import json; print(json.dumps({'status': 'not-packed', 'dump_size': 4}))", "inconsistent"),
    ("import json, sys; sys.stdout.write(json.dumps({'status': 'unpacked', 'dump_size': 3, "
     "'dump_sha256': '00'}) + '\\nabc')", "does not match the hash"),
    ("import json; print(json.dumps({'status': 'solved', 'dump_size': 0}))", "inconsistent"),
])
def test_a_malformed_answer_from_the_child_is_a_decline(body, reason):
    outcome = W.unpack(b"x", sandbox=fake_worker(body), timeout=WAIT)
    assert outcome.status == "declined" and reason in outcome.reason and outcome.dump == b""


@engine
def test_cli_writes_the_dump_and_exits_by_status(monkeypatch, tmp_path, capsys):
    need_engine()
    monkeypatch.setattr(W, "os_sandbox", lambda refresh=False: (PASS_THROUGH, "pass-through (test)"))
    sample, out = tmp_path / "packed.exe", tmp_path / "dump.exe"
    sample.write_bytes(packed())
    assert W.main([str(sample), "--out", str(out), "--timeout", str(WAIT)]) == 0
    assert PE.map_pe(out.read_bytes()).rva_bytes(0x4000, 6) == PACKED_PLAIN
    assert json.loads(capsys.readouterr().out)["oep_rva"] == 0x4000
    plain = tmp_path / "plain.exe"
    plain.write_bytes(build_pe32(entry=0x1000 + L["teb_self"]))
    out.unlink()
    assert W.main([str(plain), "--out", str(out), "--timeout", str(WAIT)]) == 1 and not out.exists()
    assert W.main([str(tmp_path / "missing.exe")]) == 2
    assert W.main(["--layers"]) == 2
