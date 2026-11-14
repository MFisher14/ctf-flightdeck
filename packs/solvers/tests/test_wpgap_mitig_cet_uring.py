"""Independent vectors for the CET/io_uring ground-truth analyzer.

The note bytes and cBPF instructions below are hand-encoded directly from the ELF,
seccomp_data, classic-BPF, and Linux syscall ABIs.  They do not use engine serializers.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import wpgap_mitig_cet_uring as engine


# ELF64 LE: GNU/NT_GNU_PROPERTY_TYPE_0, FEATURE_1_AND uint32, IBT|SHSTK.
BOTH_CET_NOTE = bytes.fromhex(
    "040000001000000005000000474e5500"
    "020000c0040000000300000000000000"
)

# Hand-built x86-64 seccomp cBPF.  It kills an architecture mismatch, allows only
# syscall 426 (io_uring_enter), and returns EPERM for every other syscall.
ENTER_ONLY_FILTER = [
    (0x20, 0, 0, 4),
    (0x15, 1, 0, 0xC000003E),
    (0x06, 0, 0, 0x80000000),
    (0x20, 0, 0, 0),
    (0x15, 0, 1, 426),
    (0x06, 0, 0, 0x7FFF0000),
    (0x06, 0, 0, 0x00050001),
]

ENTER_ONLY_PACKED_HEX = (
    "2000000004000000150001003e0000c00600000000000080"
    "200000000000000015000001aa010000060000000000ff7f"
    "0600000001000500"
)


def _status(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "hardware": {"ibt": True, "shstk": True},
        "kernel": {"user_ibt": True, "user_shstk": True},
        "loader": {"ibt": "enabled", "shstk": "enabled", "source": "saved loader log"},
        "thread": {
            "ibt": "enabled", "shstk": "enabled", "shstk_locked": True,
            "wrss": False, "no_track": False, "source": "saved thread snapshot",
        },
        "surfaces": [],
    }
    result.update(overrides)
    return result


def _facts(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "architecture": "amd64",
        "kernel_version": "6.6.0",
        "filter_is_complete": True,
        "syscalls": {
            "setup": [2, 0, 0, 0, 0, 0],
            "enter": [3, 1, 0, 0, 0, 0],
            "register": [3, 0, 0, 0, 0, 0],
        },
        "ring": {
            "fd": 3,
            "exists": True,
            "mapped": True,
            "enabled": True,
            "sqpoll": False,
            "restricted": False,
        },
        "supported_ops": ["OPENAT", "READ", "WRITE", "SEND", "SPLICE"],
        "resources": {
            "path": True,
            "ordinary_buffer": True,
            "target_fd": False,
            "output_fd": True,
            "connected_socket": False,
            "pipe": False,
            "cqes_readable": True,
            "registered_buffer": False,
            "iovecs": False,
            "msghdr": False,
            "zc_completion": False,
            "buffer_selection": False,
            "fixed_files": False,
            "memory_dataflow": True,
            "pipe_dataflow": False,
        },
        "permissions": {"default": True},
    }
    result.update(overrides)
    return result


def _rows(report: dict[str, object]) -> dict[str, dict[str, object]]:
    return {row["op"]: row for row in report["matrix"]}  # type: ignore[index]


def test_hand_built_elf_note_declares_both_without_claiming_runtime() -> None:
    parsed = engine.parse_gnu_property_notes(BOTH_CET_NOTE)
    assert parsed["property_note_present"] is True
    assert parsed["feature_mask"] == "0x00000003"
    assert parsed["ibt"] is True and parsed["shstk"] is True
    assert parsed["scope"] == "ELF declaration only; not loader or runtime enforcement"

    unknown_bit = bytearray(BOTH_CET_NOTE)
    unknown_bit[24:28] = (7).to_bytes(4, "little")
    parsed_unknown = engine.parse_gnu_property_notes(bytes(unknown_bit))
    assert parsed_unknown["unknown_feature_bits"] == "0x00000004"

    absent = engine.parse_gnu_property_notes(b"")
    assert absent["ibt"] is None and absent["shstk"] is None


@pytest.mark.parametrize(
    "candidate",
    [
        BOTH_CET_NOTE[:-1],
        b"\x04\x00\x00",
        BOTH_CET_NOTE + b"\x00",
    ],
)
def test_malformed_notes_fail_with_declared_exception(candidate: bytes) -> None:
    with pytest.raises(engine.WpgapMitigError):
        engine.parse_gnu_property_notes(candidate)

    bad_size = bytearray(BOTH_CET_NOTE)
    bad_size[20:24] = (3).to_bytes(4, "little")
    with pytest.raises(engine.WpgapMitigError):
        engine.parse_gnu_property_notes(bytes(bad_size))


def test_declaration_loader_thread_and_endbr_are_separate_layers() -> None:
    status = _status(
        loader={"ibt": "disabled", "shstk": "disabled", "source": "saved loader decision"},
        thread={
            "ibt": "disabled", "shstk": "disabled", "shstk_locked": False,
            "wrss": False, "no_track": False, "source": "saved thread snapshot",
        },
        surfaces=[
            {
                "name": "no-endbr-indirect",
                "transfer": "indirect_jump",
                "target_endbr": False,
                "notrack": False,
            },
            {"name": "forged-ret", "transfer": "return", "shadow_return_match": False},
        ],
    )
    report = engine.analyze_cet(BOTH_CET_NOTE, status)
    assert report["declaration"]["ibt"] is True  # type: ignore[index]
    assert report["loader"]["ibt"] == "disabled"  # type: ignore[index]
    assert report["enforcement"] == {  # type: ignore[comparison-overlap]
        "ibt": "disabled",
        "shstk": "disabled",
        "basis": "saved per-thread facts only; declaration and loader state are not promoted",
    }
    assert [surface["overall"] for surface in report["surfaces"]] == ["usable", "usable"]  # type: ignore[index]
    assert any("declares IBT" in warning for warning in report["warnings"])  # type: ignore[union-attr]


def test_endbr_is_compatible_under_unknown_ibt_but_never_enables_it() -> None:
    status = _status(
        loader={"ibt": "unknown", "shstk": "unknown", "source": "no loader record"},
        thread={
            "ibt": "unknown", "shstk": "unknown", "shstk_locked": "unknown",
            "wrss": "unknown", "no_track": False, "source": "partial snapshot",
        },
        surfaces=[{
            "name": "endbr-target",
            "transfer": "indirect_jump",
            "target_endbr": True,
            "notrack": False,
        }],
    )
    report = engine.analyze_cet(BOTH_CET_NOTE, status)
    assert report["enforcement"]["ibt"] == "unknown"  # type: ignore[index]
    assert report["surfaces"][0]["entry"] == "usable"  # type: ignore[index]
    assert any(
        "does not establish" in reason
        for reason in report["surfaces"][0]["entry_reasons"]  # type: ignore[index]
    )


def test_ierae_style_facts_keep_notrack_return_and_signal_surfaces_distinct() -> None:
    status = _status(
        thread={
            "ibt": True, "shstk": True, "shstk_locked": True,
            "wrss": False, "no_track": True, "source": "custom-kernel saved status",
        },
        surfaces=[
            {
                "name": "notrack-call-target",
                "transfer": "indirect_jump",
                "target_endbr": False,
                "notrack": True,
            },
            {"name": "forged-ret", "transfer": "return", "shadow_return_match": False},
            {
                "name": "legitimate-call-return",
                "transfer": "direct_call",
                "returns": True,
                "shadow_return_match": True,
            },
            {
                "name": "saved-signal-restore",
                "transfer": "signal_restore",
                "special_runtime_authorized": True,
            },
            {
                "name": "unproven-context-restore",
                "transfer": "context_restore",
                "special_runtime_authorized": None,
            },
        ],
    )
    report = engine.analyze_cet(BOTH_CET_NOTE, status)
    assert [surface["overall"] for surface in report["surfaces"]] == [  # type: ignore[index]
        "usable", "blocked", "usable", "usable", "unknown",
    ]
    assert "cet_bypassed" not in json.dumps(report).lower()


def test_proc_status_is_thread_scoped_and_conflicts_fail_closed() -> None:
    proc = """Name:\tdemo
x86_Thread_features:\tshstk wrss
x86_Thread_features_locked:\tshstk
"""
    parsed = engine.parse_proc_status(proc)
    assert parsed["shstk"] == "enabled"
    assert parsed["wrss"] == "enabled"
    assert parsed["shstk_locked"] == "enabled"
    assert parsed["ibt"] == "unknown"

    status = _status(
        thread={
            "ibt": "unknown", "shstk": "disabled", "shstk_locked": "unknown",
            "wrss": "unknown", "no_track": "unknown", "source": "contradictory record",
        },
        proc_status=proc,
    )
    with pytest.raises(engine.WpgapMitigError, match="contradictory"):
        engine.analyze_cet(BOTH_CET_NOTE, status)


def test_shstk_may_be_locked_in_the_disabled_state() -> None:
    status = _status(
        thread={
            "ibt": False,
            "shstk": False,
            "shstk_locked": True,
            "wrss": False,
            "no_track": False,
            "source": "ARCH_SHSTK_STATUS plus lock snapshot",
        }
    )
    report = engine.analyze_cet(BOTH_CET_NOTE, status)
    assert report["thread"]["shstk"] == "disabled"  # type: ignore[index]
    assert report["thread"]["shstk_locked"] == "enabled"  # type: ignore[index]


def test_known_filter_and_precreated_ring_produce_exact_matrix() -> None:
    report = engine.analyze_io_uring(ENTER_ONLY_FILTER, _facts())
    assert report["syscalls"]["setup"]["action"] == "errno(1)"  # type: ignore[index]
    assert report["syscalls"]["enter"]["action"] == "allow"  # type: ignore[index]
    assert report["syscalls"]["register"]["action"] == "errno(1)"  # type: ignore[index]
    assert report["ring_gate"]["setup_required"] is False  # type: ignore[index]
    assert report["submission"]["verdict"] == "usable"  # type: ignore[index]

    rows = _rows(report)
    assert {name: rows[name]["verdict"] for name in rows} == {
        "OPENAT": "usable",
        "READ": "usable",
        "SEND": "blocked",
        "SPLICE": "blocked",
        "WRITE": "usable",
    }
    assert report["reach"] == {  # type: ignore[comparison-overlap]
        "open_reach": "usable",
        "read_reach": "usable",
        "emit_reach": "usable",
        "orw_equivalent": "usable",
        "target_fd": "usable",
        "splice_file_to_pipe": "blocked",
        "splice_pipe_to_output": "blocked",
        "connected_memory_route": "usable",
        "connected_pipe_route": "blocked",
    }
    assert "seccomp_visibility" in report
    assert "bypass" not in report["analysis"]  # type: ignore[operator]


def test_packed_known_filter_vector_matches_instruction_vector() -> None:
    packed = bytes.fromhex(ENTER_ONLY_PACKED_HEX)
    left = engine.analyze_io_uring(ENTER_ONLY_FILTER, _facts())
    right = engine.analyze_io_uring(packed, _facts())
    assert left["syscalls"] == right["syscalls"]
    assert left["reach"] == right["reach"]


def test_exact_seccomp_argument_tuple_changes_enter_decision() -> None:
    # Exact fd-7 allowlist. seccomp_data.args[0] starts at byte offset 16.
    fd7_filter = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x15, 0, 3, 426),
        (0x20, 0, 0, 16),
        (0x15, 0, 1, 7),
        (0x06, 0, 0, 0x7FFF0000),
        (0x06, 0, 0, 0x00050001),
    ]
    allowed_facts = _facts()
    allowed_ring = dict(allowed_facts["ring"])  # type: ignore[arg-type]
    allowed_ring["fd"] = 7
    allowed_facts["ring"] = allowed_ring
    allowed_facts["syscalls"] = {
        "setup": [0, 0, 0, 0, 0, 0],
        "enter": [7, 1, 0, 0, 0, 0],
        "register": [7, 0, 0, 0, 0, 0],
    }
    denied_facts = _facts()
    denied_ring = dict(denied_facts["ring"])  # type: ignore[arg-type]
    denied_ring["fd"] = 8
    denied_facts["ring"] = denied_ring
    denied_facts["syscalls"] = {
        "setup": [0, 0, 0, 0, 0, 0],
        "enter": [8, 1, 0, 0, 0, 0],
        "register": [8, 0, 0, 0, 0, 0],
    }
    assert engine.analyze_io_uring(fd7_filter, allowed_facts)["submission"]["verdict"] == "usable"  # type: ignore[index]
    assert engine.analyze_io_uring(fd7_filter, denied_facts)["submission"]["verdict"] == "blocked"  # type: ignore[index]


def test_normal_enter_must_target_ring_and_submit_at_least_one_sqe() -> None:
    zero_submit = _facts()
    zero_submit["syscalls"] = {
        "setup": [0, 0, 0, 0, 0, 0],
        "enter": [3, 0, 0, 0, 0, 0],
        "register": [3, 0, 0, 0, 0, 0],
    }
    assert engine.analyze_io_uring(ENTER_ONLY_FILTER, zero_submit)["submission"]["verdict"] == "blocked"  # type: ignore[index]

    wrong_fd = _facts()
    wrong_fd["syscalls"] = {
        "setup": [0, 0, 0, 0, 0, 0],
        "enter": [9, 1, 0, 0, 0, 0],
        "register": [3, 0, 0, 0, 0, 0],
    }
    assert engine.analyze_io_uring(ENTER_ONLY_FILTER, wrong_fd)["submission"]["verdict"] == "blocked"  # type: ignore[index]


def test_disabled_ring_requires_exact_enable_rings_registration() -> None:
    allow_all = [(0x06, 0, 0, 0x7FFF0000)]
    ring = {
        "fd": 3,
        "exists": True,
        "mapped": True,
        "enabled": False,
        "enable_policy": True,
        "sqpoll": False,
        "restricted": False,
    }
    wrong = _facts(ring=ring)
    wrong["syscalls"] = {
        "setup": [2, 0, 0, 0, 0, 0],
        "enter": [3, 1, 0, 0, 0, 0],
        "register": [3, 0, 0, 0, 0, 0],  # REGISTER_BUFFERS, not ENABLE_RINGS
    }
    wrong_report = engine.analyze_io_uring(allow_all, wrong)
    assert wrong_report["ring_gate"]["enabled"] == "blocked"  # type: ignore[index]

    correct = _facts(ring=ring)
    correct["syscalls"] = {
        "setup": [2, 0, 0, 0, 0, 0],
        "enter": [3, 1, 0, 0, 0, 0],
        "register": [3, 12, 0, 0, 0, 0],  # IORING_REGISTER_ENABLE_RINGS
    }
    correct_report = engine.analyze_io_uring(allow_all, correct)
    assert correct_report["ring_gate"]["enabled"] == "usable"  # type: ignore[index]
    assert correct_report["submission"]["verdict"] == "usable"  # type: ignore[index]


def test_unknown_enabled_state_is_not_downgraded_by_denied_register() -> None:
    all_errno = [(0x06, 0, 0, 0x00050001)]
    ring = {
        "fd": 3,
        "exists": True,
        "mapped": True,
        "enabled": None,
        "enable_policy": True,
        "sqpoll": False,
        "restricted": False,
    }
    facts = _facts(ring=ring)
    facts["syscalls"] = {
        "setup": [2, 0, 0, 0, 0, 0],
        "enter": [3, 1, 0, 0, 0, 0],
        "register": [3, 12, 0, 0, 0, 0],
    }
    report = engine.analyze_io_uring(all_errno, facts)
    assert report["ring_gate"]["enabled"] == "unknown"  # type: ignore[index]


def test_user_notif_stays_unknown_until_exact_outcome_is_supplied() -> None:
    mediated = list(ENTER_ONLY_FILTER)
    mediated[5] = (0x06, 0, 0, 0x7FC00007)
    unresolved = engine.analyze_io_uring(mediated, _facts())
    assert unresolved["syscalls"]["enter"]["action"] == "user_notif(7)"  # type: ignore[index]
    assert unresolved["submission"]["verdict"] == "unknown"  # type: ignore[index]
    assert unresolved["reach"]["orw_equivalent"] == "unknown"  # type: ignore[index]

    continued_facts = _facts(supervisor_outcomes={"enter": "continue"})
    continued = engine.analyze_io_uring(mediated, continued_facts)
    assert continued["syscalls"]["enter"]["verdict"] == "usable"  # type: ignore[index]
    assert continued["reach"]["orw_equivalent"] == "usable"  # type: ignore[index]


def test_sqpoll_awake_path_and_need_wakeup_are_not_conflated() -> None:
    all_errno = [(0x06, 0, 0, 0x00050001)]
    base_ring = {
        "fd": 3,
        "exists": True,
        "mapped": True,
        "enabled": True,
        "sqpoll": True,
        "sq_thread_awake": True,
        "sq_need_wakeup": False,
        "sqpoll_nonfixed": True,
        "restricted": False,
    }
    awake_facts = _facts(ring=base_ring)
    awake = engine.analyze_io_uring(all_errno, awake_facts)
    assert awake["syscalls"]["enter"]["verdict"] == "blocked"  # type: ignore[index]
    assert awake["submission"] == {  # type: ignore[comparison-overlap]
        "verdict": "usable",
        "path": "awake SQPOLL",
        "reason": "saved status says the SQ poller is awake and SQ_NEED_WAKEUP is clear",
    }
    assert awake["reach"]["orw_equivalent"] == "usable"  # type: ignore[index]

    wake_ring = dict(base_ring)
    wake_ring["sq_need_wakeup"] = True
    wake_facts = _facts(ring=wake_ring)
    wake_facts["syscalls"] = {
        "setup": [0, 0, 0, 0, 0, 0],
        "enter": [3, 1, 0, 2, 0, 0],  # IORING_ENTER_SQ_WAKEUP
        "register": [3, 0, 0, 0, 0, 0],
    }
    wake = engine.analyze_io_uring(all_errno, wake_facts)
    assert wake["submission"]["verdict"] == "blocked"  # type: ignore[index]
    assert wake["reach"]["orw_equivalent"] == "blocked"  # type: ignore[index]


def test_sqpoll_fd_ops_require_nonfixed_feature_or_registered_files() -> None:
    all_errno = [(0x06, 0, 0, 0x00050001)]
    ring = {
        "fd": 3,
        "exists": True,
        "mapped": True,
        "enabled": True,
        "sqpoll": True,
        "sq_thread_awake": True,
        "sq_need_wakeup": False,
        "sqpoll_nonfixed": False,
        "restricted": False,
    }
    no_fixed = engine.analyze_io_uring(all_errno, _facts(ring=ring))
    assert no_fixed["submission"]["verdict"] == "usable"  # type: ignore[index]
    assert _rows(no_fixed)["READ"]["sqpoll_file_gate"] == "blocked"
    assert no_fixed["reach"]["orw_equivalent"] == "blocked"  # type: ignore[index]

    resources = dict(_facts()["resources"])  # type: ignore[arg-type]
    resources["fixed_files"] = True
    fixed = engine.analyze_io_uring(all_errno, _facts(ring=ring, resources=resources))
    assert _rows(fixed)["READ"]["sqpoll_file_gate"] == "usable"
    assert fixed["reach"]["orw_equivalent"] == "usable"  # type: ignore[index]


def test_ring_restriction_allowlist_is_independent_of_seccomp() -> None:
    ring = {
        "fd": 3,
        "exists": True,
        "mapped": True,
        "enabled": True,
        "sqpoll": False,
        "restricted": True,
        "allowed_ops": ["READ"],
        "allowed_sqe_flags": 0,
        "required_sqe_flags": 0,
    }
    resources = dict(_facts()["resources"])  # type: ignore[arg-type]
    resources["target_fd"] = True
    report = engine.analyze_io_uring(
        ENTER_ONLY_FILTER,
        _facts(ring=ring, resources=resources, supported_ops=["OPENAT", "READ", "WRITE"]),
    )
    rows = _rows(report)
    assert rows["READ"]["verdict"] == "usable"
    assert rows["OPENAT"]["verdict"] == "blocked"
    assert rows["WRITE"]["verdict"] == "blocked"
    assert report["reach"]["orw_equivalent"] == "blocked"  # type: ignore[index]


def test_version_floor_is_only_a_warning_and_probe_wins() -> None:
    facts = _facts(kernel_version="5.4.0", supported_ops=["OPENAT", "READ", "WRITE"])
    report = engine.analyze_io_uring(ENTER_ONLY_FILTER, facts)
    assert _rows(report)["OPENAT"]["kernel_support"] == "usable"
    assert any("OPENAT" in warning and "5.6" in warning for warning in report["warnings"])  # type: ignore[union-attr]


def test_orw_requires_an_explicit_connected_dataflow() -> None:
    resources = dict(_facts()["resources"])  # type: ignore[arg-type]
    resources["memory_dataflow"] = False
    report = engine.analyze_io_uring(ENTER_ONLY_FILTER, _facts(resources=resources))
    assert report["reach"]["open_reach"] == "usable"  # type: ignore[index]
    assert report["reach"]["read_reach"] == "usable"  # type: ignore[index]
    assert report["reach"]["emit_reach"] == "usable"  # type: ignore[index]
    assert report["reach"]["connected_memory_route"] == "blocked"  # type: ignore[index]
    assert report["reach"]["orw_equivalent"] == "blocked"  # type: ignore[index]


def test_wrong_audit_arch_and_incomplete_filter_remain_conservative() -> None:
    wrong_arch = engine.analyze_io_uring(
        ENTER_ONLY_FILTER,
        _facts(architecture="aarch64"),
    )
    assert wrong_arch["syscalls"]["enter"]["action"] == "kill_process"  # type: ignore[index]
    assert wrong_arch["submission"]["verdict"] == "blocked"  # type: ignore[index]

    incomplete = engine.analyze_io_uring(
        [(0x06, 0, 0, 0x7FFF0000)],
        _facts(filter_is_complete=False),
    )
    assert incomplete["syscalls"]["enter"]["verdict"] == "unknown"  # type: ignore[index]
    assert incomplete["reach"]["orw_equivalent"] == "unknown"  # type: ignore[index]


@pytest.mark.parametrize(
    "filter_source,facts",
    [
        ([], _facts()),
        ([(0x06, 0, 0, 0x7FFF0000)], _facts(supported_ops="READ")),
        ([(0x06, 0, 0, 0x7FFF0000)], _facts(syscalls={"enter": [3]})),
        ([(0x06, 0, 0, 0x7FFF0000)], _facts(ring={"exists": "maybe"})),
    ],
)
def test_invalid_io_uring_inputs_expose_only_declared_exception(
    filter_source: object, facts: dict[str, object]
) -> None:
    with pytest.raises(engine.WpgapMitigError):
        engine.analyze_io_uring(filter_source, facts)  # type: ignore[arg-type]


def test_document_and_guarded_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    document = {
        "mode": "cet",
        "note_hex": BOTH_CET_NOTE.hex(),
        "runtime": _status(),
        "elf_class": 64,
        "endian": "little",
    }
    assert engine.analyze_document(document)["declaration"]["shstk"] is True  # type: ignore[index]

    note_path = tmp_path / "property.note"
    note_path.write_bytes(BOTH_CET_NOTE)
    status_path = tmp_path / "status.json"
    status_path.write_text(json.dumps(_status()), encoding="utf-8")
    assert engine.main(["cet", str(note_path), str(status_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["enforcement"]["shstk"] == "enabled"

    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    assert engine.main(["cet"]) == 2
    assert engine.main(["document", str(tmp_path / "missing.json")]) == 2

