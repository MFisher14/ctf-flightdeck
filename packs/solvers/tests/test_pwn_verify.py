from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

from contract import PayloadBuild  # noqa: E402
import format_string_builder as fmt  # noqa: E402
import heap_families as heap  # noqa: E402
import kernel_pwn as kernel  # noqa: E402
import multiarch as multi  # noqa: E402
import userland_chains as userland  # noqa: E402
import pwn_verify as verify  # noqa: E402
import windows_pwn as windows  # noqa: E402


def _fixture() -> PayloadBuild:
    return PayloadBuild(
        b"HEADR5B_MARKER",
        {"header": 0, "marker": 4},
        {"header": 4, "marker": 10},
        architecture="fixture",
        strategy="verification-fixture",
        base_address=0x400000,
        metadata={"delivery": "none"},
    )


def test_static_roundtrip_hashes_payload_map_and_exact_marker() -> None:
    build = _fixture()
    record = verify.verify_payload(
        "fixture.builder", build, marker_label="marker", expected_marker=b"R5B_MARKER",
    )
    assert record.payload_sha256 == hashlib.sha256(build.payload).hexdigest()
    assert record.marker_sha256 == hashlib.sha256(b"R5B_MARKER").hexdigest()
    assert record.described_bytes == len(build.payload)
    assert record.overlap_bytes == 0
    assert record.evidence == "static-roundtrip"
    assert record.as_dict()["name"] == "fixture.builder"


def test_heap_rich_result_uses_only_explicit_adapter() -> None:
    result = heap.build_tcache_poison(
        glibc_version="2.37", freed_chunk_addr=0x404000,
        target_addr=0x405000, chunk_size=0x90,
    )
    record = verify.verify_payload("heap.poison", result)
    assert record.strategy == "tcache_poison"
    assert record.length == len(result.payload)
    with pytest.raises(verify.VerificationError, match="no audited adapter"):
        verify.coerce_payload((b"bytes", {"x": 0}))


def test_marker_and_payload_contract_fail_closed() -> None:
    with pytest.raises(verify.VerificationError, match="declared width"):
        verify.verify_payload("x", _fixture(), marker_label="absent")
    with pytest.raises(verify.VerificationError, match="do not match"):
        verify.verify_payload("x", _fixture(), marker_label="marker", expected_marker=b"wrong")
    with pytest.raises(verify.VerificationError, match="requires marker_label"):
        verify.verify_payload("x", _fixture(), expected_marker=b"R5B_MARKER")
    empty = PayloadBuild(b"", {}, architecture="fixture", strategy="empty")
    with pytest.raises(verify.VerificationError, match="1.."):
        verify.verify_payload("x", empty)


def test_manifest_reports_public_builder_coverage_and_stable_json() -> None:
    sample_name = "multiarch.build_marker_shellcode"
    manifest = verify.make_manifest(
        [multi], {sample_name: multi.build_marker_shellcode("arm", b"R5B")},
    )
    assert sample_name in manifest.exercised
    assert "multiarch.build_execve_shellcode" in manifest.missing
    assert not manifest.complete
    assert json.loads(manifest.to_json())["schema"] == "r5b-verification-v1"
    assert manifest.to_json() == manifest.to_json()
    with pytest.raises(verify.VerificationError, match="unexercised"):
        verify.require_complete(manifest)

    builders = verify.public_builders(multi)
    # This synthetic mapping tests only the manifest's set arithmetic.  It is
    # intentionally not evidence that each differently named builder ran; real
    # builder samples are supplied by their dedicated deterministic test files.
    complete_samples = {
        name: multi.build_marker_shellcode("arm", b"R5B") for name in builders
    }
    complete = verify.make_manifest([multi], complete_samples)
    assert complete.complete
    verify.require_complete(complete)


def test_manifest_rejects_unknown_sample_names() -> None:
    with pytest.raises(verify.VerificationError, match="non-builders"):
        verify.make_manifest([multi], {"multiarch.not_a_builder": _fixture()})


def test_inventory_enumerates_every_payload_builder_lane_without_execution_claims() -> None:
    modules = (heap, userland, fmt, kernel, windows, multi)
    manifest = verify.make_manifest(modules, {})
    expected_prefixes = {
        "heap_families", "userland_chains", "format_string_builder",
        "kernel_pwn", "windows_pwn", "multiarch",
    }
    assert {name.split(".", 1)[0] for name in manifest.builders} == expected_prefixes
    assert manifest.missing == manifest.builders
    assert not manifest.records and not manifest.complete
    assert all(name.rsplit(".", 1)[1].startswith("build_") for name in manifest.builders)

    marker = multi.build_marker_shellcode("riscv64", b"R5B_INVENTORY")
    static_only = verify.make_manifest(
        modules, {"multiarch.build_marker_shellcode": marker},
    )
    assert static_only.records[0].evidence == "static-roundtrip"
    assert "emulat" not in static_only.records[0].evidence


def test_fixed_docker_argv_has_every_isolation_control(tmp_path: Path) -> None:
    (tmp_path / verify.ENVELOPE_NAME).write_text("{}", encoding="ascii")
    argv = verify.docker_roundtrip_argv(tmp_path)
    assert argv[:4] == ("docker", "run", "--pull=never", "--rm")
    assert ("--network", "none") == argv[argv.index("--network"):argv.index("--network") + 2]
    assert "--read-only" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--pids-limit") + 1] == "64"
    assert argv[argv.index("--memory") + 1] == "256m"
    assert argv[argv.index("--mount") + 1].endswith(",dst=/work,readonly")
    assert verify.DOCKER_IMAGE in argv
    assert "sh" not in argv and "bash" not in argv


def test_sacrificial_runner_writes_canonical_envelope_and_asserts_marker(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(argv, *, check, capture_output, timeout):
        observed["argv"] = tuple(argv)
        observed["check"] = check
        observed["timeout"] = timeout
        mount = argv[argv.index("--mount") + 1]
        source = next(part[4:] for part in mount.split(",") if part.startswith("src="))
        envelope = json.loads((Path(source) / verify.ENVELOPE_NAME).read_text("utf-8"))
        payload = base64.b64decode(envelope["payload_b64"], validate=True)
        assert hashlib.sha256(payload).hexdigest() == envelope["payload_sha256"]
        marker = base64.b64decode(envelope["marker_b64"], validate=True)
        return subprocess.CompletedProcess(argv, 0, stdout=marker, stderr=b"")

    monkeypatch.setattr(verify.subprocess, "run", fake_run)
    marker = b"R5B_MOCK_CONTAINER_OK\n"
    record = verify.run_sacrificial_roundtrip(_fixture(), marker=marker, timeout=9)
    assert record.evidence == "container-static-roundtrip"
    assert record.marker_sha256 == hashlib.sha256(marker).hexdigest()
    assert observed["check"] is False and observed["timeout"] == 9.0


def test_sacrificial_runner_constraints_and_marker_mismatch(monkeypatch) -> None:
    with pytest.raises(verify.VerificationError, match="immutable bytes"):
        verify.run_sacrificial_roundtrip(_fixture(), marker=bytearray(b"x"))
    with pytest.raises(verify.VerificationError, match="1..90"):
        verify.run_sacrificial_roundtrip(_fixture(), timeout=0)

    monkeypatch.setattr(
        verify.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=b"wrong", stderr=b""),
    )
    with pytest.raises(verify.VerificationError, match="marker mismatch"):
        verify.run_sacrificial_roundtrip(_fixture(), marker=b"expected")


@pytest.mark.skipif(
    os.environ.get("CTF_R5B_DOCKER_VERIFY") != "1",
    reason="set CTF_R5B_DOCKER_VERIFY=1 for the fixed networkless container",
)
def test_real_sacrificial_static_roundtrip_in_already_local_image() -> None:
    marker = b"R5B_REAL_CONTAINER_ROUNDTRIP_OK\n"
    record = verify.run_sacrificial_roundtrip(_fixture(), marker=marker)
    assert record.evidence == "container-static-roundtrip"
    assert record.marker_sha256 == hashlib.sha256(marker).hexdigest()


def _previously_structural_only_builds() -> dict[str, object]:
    """Public payload APIs whose bytes cannot meaningfully execute by themselves."""

    return {
        "heap_dispatch": heap.build_heap(
            "tcache-poisoning", glibc_version="2.35",
            freed_chunk_addr=0x55555000, chunk_size=0x90, target_addr=0x404040,
        ),
        "multiarch_call_rop": multi.build_call_rop(
            "aarch64", loader_gadget=0x1000, function=0x2000,
            arguments=(1, 2), continuation=0x3000,
        ),
        "multiarch_syscall_rop": multi.build_syscall_rop(
            "riscv64", loader_gadget=0x1000, syscall_gadget=0x2000,
            syscall_number=64, arguments=(1, 0x4000, 8), continuation=0x3000,
        ),
    }


def test_structural_only_cross_lane_builds_have_static_evidence_without_execution_claims() -> None:
    for name, build in _previously_structural_only_builds().items():
        record = verify.verify_payload(name, build)
        assert record.evidence == "static-roundtrip"
        assert record.length == len(verify.coerce_payload(build).payload)


@pytest.mark.skipif(
    os.environ.get("CTF_R5B_DOCKER_VERIFY") != "1",
    reason="set CTF_R5B_DOCKER_VERIFY=1 for fixed cross-lane structural verification",
)
def test_structural_only_cross_lane_builds_roundtrip_in_fixed_container() -> None:
    for name, build in _previously_structural_only_builds().items():
        marker = f"R5B_{name}_OK\n".encode()
        record = verify.run_sacrificial_roundtrip(build, marker=marker)
        assert record.evidence == "container-static-roundtrip"
