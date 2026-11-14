"""Deterministic coverage for the r5b seccomp pattern analyzer and plan builders."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

from contract import PayloadBuild  # noqa: E402
import pwn_seccomp as base  # noqa: E402
import seccomp_patterns as patterns  # noqa: E402


def packed(program, *, endian: str = "little") -> bytes:
    prefix = "<" if endian == "little" else ">"
    return b"".join(struct.pack(prefix + "HBBI", row.code, row.jt, row.jf, row.k)
                    for row in program)


def action_filter(actions: list[tuple[int, int]], *, guard_arch: bool = True):
    """Build arch guard + sequential nr/action pairs + EPERM default."""
    rows = []
    if guard_arch:
        rows += [
            base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 4),
            base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 1, 0,
                             base.AUDIT_ARCH["amd64"]),
            base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_KILL_PROCESS),
        ]
    rows.append(base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0))
    for number, action in actions:
        rows.append(base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1, number))
        rows.append(base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, action))
    rows.append(base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 1))
    base.validate_program(rows)
    return rows


def broad_report():
    numbers = patterns.syscall_catalog("amd64")
    allowed = ["read", "write", "openat", "dup2", "mprotect", "execve"]
    program = action_filter([(numbers[name], base.SECCOMP_RET_ALLOW) for name in allowed])
    return patterns.analyze_seccomp_patterns(program, architecture="amd64")


def assert_plan(result: PayloadBuild, strategy: str) -> list[dict[str, object]]:
    payload, placements = result
    assert payload == result.payload and placements == result.placements
    assert result.strategy == strategy
    assert result.metadata["review_only"] == "true"
    assert all(placements[name] + result.widths[name] <= len(payload)
               for name in result.widths)
    rows = [json.loads(line) for line in payload.decode().splitlines()]
    assert rows[0]["inert"] is True
    assert rows[-1]["never_execute_or_deliver"] is True
    return rows


def test_raw_and_decoded_filters_produce_same_arch_aware_orw_report():
    numbers = patterns.syscall_catalog("amd64")
    program = action_filter([
        (numbers["read"], base.SECCOMP_RET_ALLOW),
        (numbers["write"], base.SECCOMP_RET_ALLOW),
        (numbers["openat"], base.SECCOMP_RET_ALLOW),
    ])
    decoded = patterns.analyze_seccomp_patterns(program, architecture="amd64")
    raw = patterns.analyze_seccomp_patterns(packed(program), architecture="amd64")
    assert raw == decoded
    assert decoded["structural"]["loads_audit_arch"] is True
    assert decoded["cross_arch"]["i386"] == []
    assert decoded["capabilities"]["openers"] == ["openat"]
    assert decoded["capabilities"]["allowed_compositions"] == [
        "path-open-read-output", "inherited-fd-read-output",
    ]
    route = decoded["capabilities"]["orw_routes"][0]
    assert route == {
        "kind": "buffered", "open": "openat", "read": "read", "write": "write",
    }
    assert decoded["structural"]["has_effective_arch_guard"] is True
    assert decoded["decisions"]["execve"]["classification"] == "blocked_in_sampled_domain"
    assert decoded["limits"]["sampled_not_symbolic"] is True


def test_argument_filter_detects_partial_64bit_check_and_wx_case():
    nr = patterns.syscall_catalog("amd64")["mprotect"]
    program = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 3, nr),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 32),  # args[2] low32
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1, 7),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 13),
    ]
    report = patterns.analyze_seccomp_patterns(program, kernel_version="4.8")
    decision = report["decisions"]["mprotect"]
    assert decision["classification"] == "conditionally_allowed"
    assert "mprotect.prot_7" in decision["direct_samples"]
    assert "mprotect.prot_5" not in decision["direct_samples"]
    weaknesses = report["argument_filter_weaknesses"]
    assert any(row["kind"] == "partial_64bit_argument_check" and row["argument"] == "arg2"
               for row in weaknesses)
    assert any(row["kind"] == "writable_executable_memory_allowed" for row in weaknesses)
    with pytest.raises(patterns.SeccompPatternError, match="exact mprotect arguments"):
        patterns.build_mprotect_plan(
            report, page_address=0x4000, length=0x1000, protection=6,
        )


def test_x32_and_cross_arch_confusion_are_reported_not_claimed_symbolic():
    execve = patterns.syscall_catalog("amd64")["execve"]
    program = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1, execve),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 1),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
    ]
    report = patterns.analyze_seccomp_patterns(program, kernel_version="4.8")
    assert report["decisions"]["execve"]["classification"] == "blocked_in_sampled_domain"
    assert "execve" in report["x32"]["differential_bypasses"]
    assert report["cross_arch"]["i386"]
    kinds = {row["kind"] for row in report["argument_filter_weaknesses"]}
    assert {"missing_arch_guard", "cross_arch_direct_paths", "x32_differential_bypass"} <= kinds


def test_user_notify_trace_and_log_remain_distinct():
    numbers = patterns.syscall_catalog("amd64")
    program = action_filter([
        (numbers["read"], base.SECCOMP_RET_USER_NOTIF | 7),
        (numbers["write"], base.SECCOMP_RET_TRACE | 9),
        (numbers["openat"], base.SECCOMP_RET_LOG),
    ])
    report = patterns.analyze_seccomp_patterns(program, kernel_version="4.8")
    assert report["decisions"]["read"]["classification"] == "externally_mediated"
    assert report["decisions"]["write"]["classification"] == "externally_mediated"
    assert report["decisions"]["openat"]["classification"] == "always_allowed_in_sampled_domain"
    assert "read" in report["action_buckets"]["user_notif"]
    assert "write" in report["action_buckets"]["trace"]
    assert "openat" in report["action_buckets"]["log"]
    assert report["trace_semantics"]["seccomp_rechecked_after_ptrace_change"] is True
    result = patterns.build_supervisor_review_plan(report)
    rows = assert_plan(result, "seccomp-supervisor-review")
    assert {row.get("action") for row in rows[1:-1]} == {"user_notif", "trace", "log"}


def test_orw_fd_reuse_mprotect_exec_and_explicit_plan_builders():
    report = broad_report()
    orw = patterns.build_orw_plan(report, path="/flag.r5b", max_bytes=512)
    rows = assert_plan(orw, "seccomp-orw-review")
    assert [row.get("syscall") for row in rows[1:-1]] == ["openat", "read", "write"]
    assert "/flag.r5b" in orw.payload.decode()

    fd = patterns.build_fd_reuse_plan(
        report, source_fd=7, destination_fd=100, output_fd=1,
        buffer_address=0x20000, max_bytes=512,
    )
    rows = assert_plan(fd, "seccomp-fd-reuse-review")
    assert [row.get("syscall") for row in rows[1:-1]] == ["dup2", "read", "write"]
    assert rows[1]["arguments"] == ["7", "100"]
    assert rows[2]["arguments"] == ["100", "controlled_buffer", "512"]
    assert rows[3]["arguments"] == ["1", "controlled_buffer", "512"]
    assert rows[2]["validated_numeric_arguments"][:3] == [
        "0x0000000000000064", "0x0000000000020000", "0x0000000000000200",
    ]
    assert rows[3]["validated_numeric_arguments"][0] == "0x0000000000000001"

    memory = patterns.build_mprotect_plan(
        report, page_address=0x404000, length=0x1000, protection=7,
    )
    rows = assert_plan(memory, "seccomp-mprotect-review")
    assert rows[1]["arguments"] == ["0x404000", "0x1000", "0x7"]

    execute = patterns.build_exec_plan(report, path="/bin/true")
    rows = assert_plan(execute, "seccomp-exec-review")
    assert rows[1]["syscall"] == "execve"

    explicit = patterns.build_allowed_composition_plan(
        report, syscalls=["openat", "read", "write"], purpose="review ORW dependency",
    )
    rows = assert_plan(explicit, "seccomp-explicit-composition-review")
    assert [row.get("syscall") for row in rows[1:-1]] == ["openat", "read", "write"]


def test_inherited_fd_orw_and_fail_closed_paths():
    numbers = patterns.syscall_catalog("amd64")
    report = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["read"], base.SECCOMP_RET_ALLOW),
        (numbers["write"], base.SECCOMP_RET_ALLOW),
    ]))
    plan = patterns.build_orw_plan(report, assumed_fd=9)
    rows = assert_plan(plan, "seccomp-orw-review")
    assert [row.get("syscall") for row in rows[1:-1]] == ["read", "write"]
    assert "descriptor 9" in plan.metadata["constraints_json"]

    with pytest.raises(patterns.SeccompPatternError, match="inherited-FD"):
        patterns.build_orw_plan(report, allow_inherited_fd=False)
    with pytest.raises(patterns.SeccompPatternError, match="mprotect"):
        patterns.build_mprotect_plan(report, page_address=0x4000, length=0x1000)
    with pytest.raises(patterns.SeccompPatternError, match="execve"):
        patterns.build_exec_plan(report)
    with pytest.raises(patterns.SeccompPatternError, match="not directly reachable"):
        patterns.build_allowed_composition_plan(report, syscalls=["execve"])
    with pytest.raises(patterns.SeccompPatternError):
        patterns.decode_filter(b"bad")


def test_sendfile_only_route_is_modeled_as_one_copy_not_buffer_write():
    numbers = patterns.syscall_catalog("amd64")
    report = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["openat"], base.SECCOMP_RET_ALLOW),
        (numbers["sendfile"], base.SECCOMP_RET_ALLOW),
    ]))
    plan = patterns.build_orw_plan(report, path="/flag")
    rows = assert_plan(plan, "seccomp-orw-review")
    assert [row.get("syscall") for row in rows[1:-1]] == ["openat", "sendfile"]
    assert "copy file bytes directly" in rows[2]["intent"]
    assert report["capabilities"]["orw_routes"] == [
        {"kind": "sendfile", "open": "openat", "transfer": "sendfile"},
    ]


def test_openat2_pread_and_writev_keep_their_distinct_argument_shapes():
    numbers = patterns.syscall_catalog("amd64")
    report = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["openat2"], base.SECCOMP_RET_ALLOW),
        (numbers["pread64"], base.SECCOMP_RET_ALLOW),
        (numbers["writev"], base.SECCOMP_RET_ALLOW),
    ]))
    plan = patterns.build_orw_plan(report, path="/flag", max_bytes=128)
    rows = assert_plan(plan, "seccomp-orw-review")
    assert [row.get("syscall") for row in rows[1:-1]] == ["openat2", "pread64", "writev"]
    assert rows[1]["arguments"][2] == "&open_how{flags=O_RDONLY}"
    assert rows[2]["arguments"][-1] == "0"
    assert rows[3]["arguments"] == ["1", "reviewed_output_iovec", "1"]


@pytest.mark.parametrize(
    ("code", "offset", "message"),
    [
        (base.BPF_LD | base.BPF_H | base.BPF_ABS, 0, "not allowed by Linux seccomp"),
        (base.BPF_LD | base.BPF_W | base.BPF_IND, 0, "not allowed by Linux seccomp"),
        (base.BPF_LDX | base.BPF_B | base.BPF_MSH, 0, "not allowed by Linux seccomp"),
        (base.BPF_ALU | base.BPF_MOD | base.BPF_K, 3, "not allowed by Linux seccomp"),
        (base.BPF_LD | base.BPF_W | base.BPF_ABS, 2, "32-bit aligned"),
        (base.BPF_LD | base.BPF_W | base.BPF_ABS, 64, "within 64 bytes"),
    ],
)
def test_linux_seccomp_restricted_cbpf_subset_rejects_socket_only_ops(code, offset, message):
    program = [
        base.Instruction(code, 0, 0, offset),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
    ]
    with pytest.raises(patterns.SeccompPatternError, match=message):
        patterns.decode_filter(program)


def test_i386_big_endian_filter_and_only_x86_compatible_abi_are_modeled():
    numbers = patterns.syscall_catalog("i386")
    program = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 4),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 1, 0,
                         base.AUDIT_ARCH["i386"]),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_KILL_PROCESS),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1, numbers["read"]),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 1),
    ]
    report = patterns.analyze_seccomp_patterns(
        packed(program, endian="big"), architecture="i386", endian="big",
    )
    assert report["decisions"]["read"]["classification"] == "always_allowed_in_sampled_domain"
    assert report["structural"]["has_effective_arch_guard"] is True
    assert set(report["cross_arch"]) == {"amd64"}
    assert "arm" not in report["cross_arch"] and "aarch64" not in report["cross_arch"]

    aarch64 = patterns.analyze_seccomp_patterns([
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
    ], architecture="aarch64")
    assert aarch64["cross_arch"] == {}


def test_arch_load_without_a_real_restrictive_compare_is_not_a_guard():
    overwritten = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 4),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1,
                         base.AUDIT_ARCH["amd64"]),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_KILL_PROCESS),
    ]
    report = patterns.analyze_seccomp_patterns(overwritten)
    assert report["structural"]["loads_audit_arch"] is True
    assert report["structural"]["arch_comparisons"] == []
    assert report["structural"]["has_effective_arch_guard"] is False
    assert any(row["kind"] == "missing_arch_guard"
               for row in report["argument_filter_weaknesses"])

    non_guarding_compare = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 4),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 0,
                         base.AUDIT_ARCH["amd64"]),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
    ]
    report = patterns.analyze_seccomp_patterns(non_guarding_compare)
    assert report["structural"]["arch_comparisons"][0]["mismatch_is_restrictive"] is False
    assert report["structural"]["has_effective_arch_guard"] is False


def test_x32_rt_sigreturn_uses_513_override_and_no_native_table_alias():
    report = patterns.analyze_seccomp_patterns([
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
    ])
    assert report["x32"]["modeled_numbers"]["rt_sigreturn"] == (
        patterns.X32_SYSCALL_BIT | 513
    )
    assert report["x32"]["modeled_numbers"]["rt_sigreturn"] != (
        patterns.X32_SYSCALL_BIT | patterns.syscall_catalog("amd64")["rt_sigreturn"]
    )


def test_mprotect_builder_evaluates_exact_address_length_and_protection():
    nr = patterns.syscall_catalog("amd64")["mprotect"]
    program = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 7, nr),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 16),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 5, 0x404000),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 24),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 3, 0x2000),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 32),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 1, 7),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 13),
    ]
    report = patterns.analyze_seccomp_patterns(program)
    assert report["decisions"]["mprotect"]["classification"] == "blocked_in_sampled_domain"
    plan = patterns.build_mprotect_plan(
        report, page_address=0x404000, length=0x2000, protection=7,
    )
    row = assert_plan(plan, "seccomp-mprotect-review")[1]
    assert row["exact_filter_action"] == "allow"
    assert row["validated_numeric_arguments"][:3] == [
        "0x0000000000404000", "0x0000000000002000", "0x0000000000000007",
    ]
    with pytest.raises(patterns.SeccompPatternError, match="exact mprotect arguments"):
        patterns.build_mprotect_plan(
            report, page_address=0x405000, length=0x2000, protection=7,
        )
    with pytest.raises(patterns.SeccompPatternError, match="exact mprotect arguments"):
        patterns.build_mprotect_plan(
            report, page_address=0x404000, length=0x1000, protection=7,
        )


def test_fd_reuse_exact_arguments_preserve_output_and_use_distinct_input():
    numbers = patterns.syscall_catalog("amd64")
    program = [
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 4, numbers["dup2"]),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 16),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 18, 7),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 24),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 17, 16, 100),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 6, numbers["read"]),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 16),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 12, 100),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 24),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 10, 0x20000),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 32),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 9, 8, 128),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 0),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 6, numbers["write"]),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 16),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 4, 1),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 24),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 0, 2, 0x20000),
        base.Instruction(base.BPF_LD | base.BPF_W | base.BPF_ABS, 0, 0, 32),
        base.Instruction(base.BPF_JMP | base.BPF_JEQ | base.BPF_K, 1, 0, 128),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 1),
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ALLOW),
    ]
    report = patterns.analyze_seccomp_patterns(program)
    plan = patterns.build_fd_reuse_plan(
        report, source_fd=7, destination_fd=100, output_fd=1,
        buffer_address=0x20000, max_bytes=128,
    )
    rows = assert_plan(plan, "seccomp-fd-reuse-review")
    assert rows[1]["validated_numeric_arguments"][:2] == [
        "0x0000000000000007", "0x0000000000000064",
    ]
    assert rows[2]["validated_numeric_arguments"][:3] == [
        "0x0000000000000064", "0x0000000000020000", "0x0000000000000080",
    ]
    assert rows[3]["validated_numeric_arguments"][:3] == [
        "0x0000000000000001", "0x0000000000020000", "0x0000000000000080",
    ]
    with pytest.raises(patterns.SeccompPatternError, match="must be distinct"):
        patterns.build_fd_reuse_plan(report, source_fd=7, destination_fd=1, output_fd=1)
    with pytest.raises(patterns.SeccompPatternError, match="exact source/destination"):
        patterns.build_fd_reuse_plan(
            report, source_fd=7, destination_fd=101, output_fd=1,
            buffer_address=0x20000, max_bytes=128,
        )


def test_trace_recheck_is_explicitly_version_qualified():
    nr = patterns.syscall_catalog("amd64")["write"]
    program = action_filter([(nr, base.SECCOMP_RET_TRACE | 7)])
    old = patterns.analyze_seccomp_patterns(program, kernel_version="4.7.19")
    new = patterns.analyze_seccomp_patterns(program, kernel_version="4.8")
    unknown = patterns.analyze_seccomp_patterns(program)
    assert old["trace_semantics"]["seccomp_rechecked_after_ptrace_change"] is False
    assert new["trace_semantics"]["seccomp_rechecked_after_ptrace_change"] is True
    assert unknown["trace_semantics"]["seccomp_rechecked_after_ptrace_change"] is None
    assert "before Linux 4.8" in old["trace_semantics"]["detail"]
    assert "Linux 4.8+" in new["trace_semantics"]["detail"]


def test_orw_routes_never_mix_sendfile_with_buffered_read_write_products():
    numbers = patterns.syscall_catalog("amd64")
    report = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["openat"], base.SECCOMP_RET_ALLOW),
        (numbers["read"], base.SECCOMP_RET_ALLOW),
        (numbers["write"], base.SECCOMP_RET_ALLOW),
        (numbers["sendfile"], base.SECCOMP_RET_ALLOW),
    ]))
    routes = report["capabilities"]["orw_routes"]
    assert {route["kind"] for route in routes} == {"buffered", "sendfile"}
    assert all(route.get("read") != "sendfile" and route.get("write") != "sendfile"
               for route in routes)
    assert all("read" not in route and "write" not in route
               for route in routes if route["kind"] == "sendfile")


def test_plan_and_report_controlled_strings_are_bounded():
    report = broad_report()
    with pytest.raises(patterns.SeccompPatternError, match="purpose"):
        patterns.build_allowed_composition_plan(
            report, syscalls=["read"], purpose="A" * 257,
        )
    forged = json.loads(json.dumps(report))
    forged["decisions"]["read"]["direct_samples"] = ["x"] * 33
    rows = assert_plan(
        patterns.build_allowed_composition_plan(forged, syscalls=["read"]),
        "seccomp-explicit-composition-review",
    )
    assert rows[1]["allowed_samples"] != ["x"] * 33
    forged = json.loads(json.dumps(report))
    forged["filter_sha256"] = "a" * 100_000
    with pytest.raises(patterns.SeccompPatternError, match="filter_sha256"):
        patterns.build_orw_plan(forged)
    assert len(patterns.build_allowed_composition_plan(
        report, syscalls=["read"], purpose="bounded",
    ).payload) < patterns.MAX_PLAN_BYTES


def test_every_builder_recomputes_forged_derived_report_fields_from_program():
    blocked = patterns.analyze_seccomp_patterns([
        base.Instruction(base.BPF_RET | base.BPF_K, 0, 0, base.SECCOMP_RET_ERRNO | 1),
    ])
    allowed = broad_report()
    numbers = patterns.syscall_catalog("amd64")
    supervised = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["read"], base.SECCOMP_RET_USER_NOTIF),
        (numbers["write"], base.SECCOMP_RET_TRACE | 3),
        (numbers["openat"], base.SECCOMP_RET_LOG),
    ]), kernel_version="4.8")

    forged = json.loads(json.dumps(blocked))
    for field in (
        "decisions", "capabilities", "action_buckets", "trace_semantics",
        "argument_filter_weaknesses", "cross_arch", "x32", "structural",
    ):
        forged[field] = json.loads(json.dumps(
            supervised[field] if field in {"action_buckets", "trace_semantics"}
            else allowed[field]
        ))

    with pytest.raises(patterns.SeccompPatternError, match="no sampled read/output"):
        patterns.build_orw_plan(forged)
    with pytest.raises(patterns.SeccompPatternError, match="neither execve"):
        patterns.build_exec_plan(forged)
    with pytest.raises(patterns.SeccompPatternError, match="not directly reachable"):
        patterns.build_allowed_composition_plan(forged, syscalls=["read"])
    with pytest.raises(patterns.SeccompPatternError, match="exact mprotect arguments"):
        patterns.build_mprotect_plan(
            forged, page_address=0x404000, length=0x1000, protection=7,
        )
    with pytest.raises(patterns.SeccompPatternError, match="no deterministic dup2/dup3"):
        patterns.build_fd_reuse_plan(
            forged, source_fd=7, destination_fd=100, output_fd=1,
        )
    with pytest.raises(patterns.SeccompPatternError, match="no sampled USER_NOTIF"):
        patterns.build_supervisor_review_plan(forged)


def test_supervisor_builder_ignores_forged_unbounded_trace_prose():
    numbers = patterns.syscall_catalog("amd64")
    report = patterns.analyze_seccomp_patterns(action_filter([
        (numbers["write"], base.SECCOMP_RET_TRACE | 3),
    ]), kernel_version="4.8")
    report["trace_semantics"]["detail"] = "X" * (patterns.MAX_PLAN_BYTES * 2)
    plan = patterns.build_supervisor_review_plan(report)
    assert len(plan.payload) < patterns.MAX_PLAN_BYTES
    assert b"Linux 4.8+ rechecks" in plan.payload
    assert b"X" * 1024 not in plan.payload

