"""Networkless structural Docker verification for r5b seccomp/race plans.

Set ``CTF_R5B_DOCKER_VERIFY=1`` to run the already-local image.  The
container only decodes, hashes, and checks placement maps.  Compile-blocked
race source sections are asserted as data and are never compiled or executed.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import pwn_seccomp as base  # noqa: E402
import race_scaffolds as races  # noqa: E402
import seccomp_patterns as patterns  # noqa: E402


VERIFY = os.environ.get("CTF_R5B_DOCKER_VERIFY") == "1"
DOCKER_SKIP = pytest.mark.skipif(
    not VERIFY, reason="set CTF_R5B_DOCKER_VERIFY=1 for networkless Docker verification",
)
_SEQUENCE = itertools.count()


def action_filter(actions):
    rows = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 4),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 1, 0,
                         base.AUDIT_ARCH["amd64"]),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_KILL_PROCESS),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
    ]
    for number, action in actions:
        rows.append(base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1, number))
        rows.append(base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, action))
    rows.append(base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 1))
    return rows


def all_builds():
    numbers = patterns.syscall_catalog("amd64")
    report = patterns.analyze_seccomp_patterns(action_filter([
        (numbers[name], base.SECCOMP_RET_ALLOW)
        for name in ("read", "write", "openat", "dup2", "mprotect", "execve")
    ]))
    supervisor = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["read"], base.SECCOMP_RET_USER_NOTIF),
        (numbers["write"], base.SECCOMP_RET_TRACE | 3),
        (numbers["openat"], base.SECCOMP_RET_LOG),
    ]))
    plans = [
        ("seccomp.orw", "jsonl", patterns.build_orw_plan(report, path="/R5B_DOCKER_MARKER")),
        ("seccomp.fd", "jsonl", patterns.build_fd_reuse_plan(report, source_fd=7)),
        ("seccomp.mprotect", "jsonl", patterns.build_mprotect_plan(
            report, page_address=0x404000, length=0x1000)),
        ("seccomp.exec", "jsonl", patterns.build_exec_plan(report, path="/bin/true")),
        ("seccomp.composition", "jsonl", patterns.build_allowed_composition_plan(
            report, syscalls=["openat", "read", "write"])),
        ("seccomp.supervisor", "jsonl", patterns.build_supervisor_review_plan(supervisor)),
        ("race.userfaultfd", "race", races.build_userfaultfd_race_plan(
            kernel_version="6.6", fault_page_address=0x100000,
            initial_buffer=b"R5B_UFFD_A", replacement_buffer=b"R5B_UFFD_B")),
        ("race.fuse", "race", races.build_fuse_race_plan(
            kernel_version="6.6", mapped_buffer_address=0x200000,
            initial_buffer=b"R5B_FUSE_A", replacement_buffer=b"R5B_FUSE_B")),
        ("race.toctou", "race", races.build_toctou_race_plan(
            kernel_version="6.6", controlled_buffer_address=0x300000,
            checked_buffer=b"R5B_TOCTOU_A", used_buffer=b"R5B_TOCTOU_B")),
    ]
    return plans


def docker_argv(encoded: str, script: str) -> list[str]:
    return [
        "docker", "run", "--pull=never", "--rm", "--network", "none",
        "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "csctf-sandbox:2", "python3", "-c", script, encoded,
    ]


def test_docker_command_is_fixed_pull_never_and_networkless():
    argv = docker_argv("fixture", "pass")
    assert argv[:4] == ["docker", "run", "--pull=never", "--rm"]
    assert argv[argv.index("--network") + 1] == "none"
    cap = argv.index("--cap-drop")
    assert "--read-only" in argv and argv[cap:cap + 2] == ["--cap-drop", "ALL"]
    assert "csctf-sandbox:2" in argv


@DOCKER_SKIP
def test_all_seccomp_and_race_builders_roundtrip_without_running_generated_source():
    manifest = []
    for name, kind, result in all_builds():
        manifest.append({
            "name": name, "kind": kind,
            "payload": base64.b64encode(result.payload).decode("ascii"),
            "sha256": hashlib.sha256(result.payload).hexdigest(),
            "placements": dict(result.placements), "widths": dict(result.widths),
            "strategy": result.strategy,
        })
    encoded = base64.b64encode(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).decode("ascii")
    script = r'''
import base64, hashlib, json, struct, sys
rows = json.loads(base64.b64decode(sys.argv[1], validate=True))
assert len(rows) == 9
for row in rows:
    raw = base64.b64decode(row["payload"], validate=True)
    assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    for name, offset in row["placements"].items():
        assert 0 <= offset <= len(raw)
        if name in row["widths"]:
            assert offset + row["widths"][name] <= len(raw)
    if row["kind"] == "jsonl":
        document = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
        assert document[0]["inert"] is True
        assert document[-1]["never_execute_or_deliver"] is True
        assert all(item.get("review_only") is True for item in document[1:-1])
    else:
        assert raw[:8] == b"R5BRACE1"
        version, count = struct.unpack_from("<HH", raw, 8)
        assert version == 1 and count == 5
        cursor, sections = 12, {}
        for _ in range(count):
            cursor += (-cursor) % 8
            name_len, data_len = struct.unpack_from("<HI", raw, cursor)
            cursor += 6
            name = raw[cursor:cursor + name_len].decode("ascii")
            cursor += name_len
            sections[name] = raw[cursor:cursor + data_len]
            cursor += data_len
        assert sections["source.c"].startswith(b"#error ")
        assert b"main(" not in sections["source.c"]
        assert json.loads(sections["manifest"])["inert"] is True
        timeline = json.loads(sections["timeline"])
        assert len(timeline) >= 6
        assert any(b"R5B_" in data for name, data in sections.items() if name.startswith("buffer."))
print("R5B_SECCOMP_RACE_STRUCTURAL_OK:9")
'''
    command = docker_argv(encoded, script)
    # Give this one ephemeral verifier a name so a timeout can be cleaned up.
    name = f"csctf-r5b-seccomp-race-{os.getpid()}-{next(_SEQUENCE)}"
    command[4:4] = ["--name", name, "--stop-timeout", "1"]
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=45,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "stop", "--time", "1", name], check=False,
                       capture_output=True, text=True, timeout=5)
        subprocess.run(["docker", "rm", "--force", name], check=False,
                       capture_output=True, text=True, timeout=5)
        raise
    assert completed.returncode == 0, f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
    assert completed.stdout.strip() == "R5B_SECCOMP_RACE_STRUCTURAL_OK:9"

