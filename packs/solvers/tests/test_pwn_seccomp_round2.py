"""Synthetic offline tests for the static seccomp classic-BPF analyzer."""
import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pwn_seccomp as S  # noqa: E402


def allow_orw_program():
    """amd64 arch guard, allow read/write/openat, EPERM everything else."""
    return [
        S.Instruction(S.BPF_LD | S.BPF_W | S.BPF_ABS, 0, 0, 4),
        S.Instruction(S.BPF_JMP | S.BPF_JEQ | S.BPF_K, 1, 0, S.AUDIT_ARCH["amd64"]),
        S.Instruction(S.BPF_RET | S.BPF_K, 0, 0, S.SECCOMP_RET_KILL_PROCESS),
        S.Instruction(S.BPF_LD | S.BPF_W | S.BPF_ABS, 0, 0, 0),
        S.Instruction(S.BPF_JMP | S.BPF_JEQ | S.BPF_K, 3, 0, 0),       # read
        S.Instruction(S.BPF_JMP | S.BPF_JEQ | S.BPF_K, 2, 0, 1),       # write
        S.Instruction(S.BPF_JMP | S.BPF_JEQ | S.BPF_K, 1, 0, 257),     # openat
        S.Instruction(S.BPF_RET | S.BPF_K, 0, 0, S.SECCOMP_RET_ERRNO | 1),
        S.Instruction(S.BPF_RET | S.BPF_K, 0, 0, S.SECCOMP_RET_ALLOW),
    ]


def packed(program, endian="<"):
    return b"".join(struct.pack(endian + "HBBI", i.code, i.jt, i.jf, i.k) for i in program)


def test_parse_validate_and_interpret_libseccomp_shape():
    original = allow_orw_program()
    parsed = S.parse_sock_filters(packed(original))
    assert parsed == original
    S.validate_program(parsed)
    assert S.action_name(S.execute_filter(parsed, 0, S.AUDIT_ARCH["amd64"])) == "allow"
    assert S.action_name(S.execute_filter(parsed, 59, S.AUDIT_ARCH["amd64"])) == "errno(1)"
    assert S.action_name(S.execute_filter(parsed, 0, S.AUDIT_ARCH["i386"])) == "kill_process"
    report = S.analyze_filter(parsed, "amd64")
    assert report["allowed"] == ["read", "write", "openat"]
    assert "execve" in report["denied"]
    assert report["default_action"] == "errno(1)"
    assert report["verdict"] == "execve blocked → ORW"


def test_json_input_and_embedded_filter_discovery(tmp_path):
    program = allow_orw_program()
    rows = [i.as_dict() for i in program]
    p = tmp_path / "filter.json"
    p.write_text(json.dumps({"instructions": rows}))
    report = S.inspect_file(p, arch="amd64")
    assert report["format"] == "json"
    assert report["analysis"]["verdict"].endswith("ORW")

    prefix = b"ELF-like-prefix-seccomp-prctl" + b"\x99" * 5
    blob = prefix + packed(program) + b"trailer"
    found = S.find_embedded_filters(blob)
    assert len(found) == 1
    assert found[0]["offset"] == len(prefix)
    assert found[0]["instructions"] == program
    detection = S.detect_seccomp(blob)
    assert detection["likely_seccomp"] is True
    assert {"seccomp", "prctl"}.issubset(detection["string_markers"])


def test_raw_file_and_json_cli(tmp_path, capsys):
    p = tmp_path / "filter.bpf"
    p.write_bytes(packed(allow_orw_program()))
    assert S.main([str(p), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["analysis"]["decisions"]["execve"]["action"] == "errno(1)"
    assert result["instructions"][0]["k"] == 4


@pytest.mark.parametrize("bad", [b"", b"1234567", b"123456789"])
def test_malformed_packed_program_rejected(bad):
    with pytest.raises(S.SeccompError):
        S.parse_sock_filters(bad)


def test_escaping_jump_and_cli_error_are_guarded(tmp_path, capsys):
    bad = [S.Instruction(S.BPF_JMP | S.BPF_JA, 0, 0, 200)]
    with pytest.raises(S.SeccompError, match="escapes"):
        S.validate_program(bad)
    p = tmp_path / "bad.bpf"
    p.write_bytes(b"not-bpf")
    assert S.main([str(p)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("pwn_seccomp.py:")
    assert "Traceback" not in err


def test_interpreter_handles_alu_memory_and_x_register():
    # A=nr; M[0]=A; X=7; A=M[0]; A^=X; return A.  This exercises the reusable interpreter beyond
    # the simple JEQ trees emitted by libseccomp.
    p = [
        S.Instruction(S.BPF_LD | S.BPF_W | S.BPF_ABS, 0, 0, 0),
        S.Instruction(S.BPF_ST, 0, 0, 0),
        S.Instruction(S.BPF_LDX | S.BPF_IMM, 0, 0, 7),
        S.Instruction(S.BPF_LD | S.BPF_MEM, 0, 0, 0),
        S.Instruction(S.BPF_ALU | S.BPF_XOR | S.BPF_X, 0, 0, 0),
        S.Instruction(S.BPF_RET | S.BPF_A, 0, 0, 0),
    ]
    assert S.execute_filter(p, 10, S.AUDIT_ARCH["amd64"]) == 13
