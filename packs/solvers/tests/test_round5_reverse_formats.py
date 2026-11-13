from __future__ import annotations

import json
import random
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import reverse_formats as R  # noqa: E402


def leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def section(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + leb(len(body)) + body


def wasm_fixture() -> bytes:
    type_sec = section(1, b"\x01\x60\x00\x00")
    function_sec = section(3, b"\x01\x00")
    export = section(7, b"\x01\x03run\x00\x00")
    code = section(10, b"\x01\x02\x00\x0b")
    return b"\0asm\x01\0\0\0" + type_sec + function_sec + export + code


def ebpf_fixture() -> bytes:
    # mov64 r0,42 ; call map_lookup_elem(1) ; exit
    return (struct.pack("<BBhi", 0xB7, 0, 0, 42)
            + struct.pack("<BBhi", 0x85, 0, 0, 1)
            + struct.pack("<BBhi", 0x95, 0, 0, 0))


def test_wasm_sections_exports_and_code_are_strict():
    report = R.parse_wasm(wasm_fixture())
    assert report["verified_structure"] is True
    assert report["exports"] == [{"name": "run", "kind": 0, "index": 0}]
    assert len(report["code_bodies"]) == 1
    bad = wasm_fixture()[:-1]
    with pytest.raises(ValueError):
        R.parse_wasm(bad)
    # Overlong/non-canonical LEB must not acquire a second interpretation.
    with pytest.raises(ValueError, match="non-canonical"):
        R.parse_wasm(b"\0asm\x01\0\0\0\x00\x80\x00")


def test_dotnet_metadata_matches_dnfile_real_fixture():
    path = REPO / "tests" / "fixtures" / "mobile_code" / "Fix.dll"
    ours = R.parse_dotnet_metadata(path.read_bytes())
    import dnfile
    theirs = dnfile.dnPE(str(path)).net.metadata
    assert ours["runtime_version"] == "v4.0.30319"
    assert {item["name"].encode() for item in ours["streams"]} == set(theirs.streams)
    # A valid-looking second root is ambiguity, not a silently selected value.
    with pytest.raises(ValueError, match="multiple valid"):
        R.parse_dotnet_metadata(path.read_bytes() + path.read_bytes()[ours["root_offset"]:])
    scan = R.analyze_languages(path.read_bytes())
    assert scan["languages"][0]["language"] == ".NET IL"
    assert scan["languages"][0]["verified"] is True


def test_ebpf_crosschecks_capstone_and_rejects_bad_targets():
    report = R.parse_ebpf(ebpf_fixture())
    assert report["helper_calls"][0]["name"] == "map_lookup_elem"
    assert report["exit_indices"] == [2]
    from capstone import CS_ARCH_BPF, CS_MODE_BPF_EXTENDED, CS_MODE_LITTLE_ENDIAN, Cs
    decoded = list(Cs(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED | CS_MODE_LITTLE_ENDIAN).disasm(ebpf_fixture(), 0))
    assert [item.mnemonic for item in decoded] == ["mov64", "call", "exit"]
    bad_jump = struct.pack("<BBhi", 0x05, 0, 10, 0) + struct.pack("<BBhi", 0x95, 0, 0, 0)
    with pytest.raises(ValueError, match="jump target"):
        R.parse_ebpf(bad_jump)
    with pytest.raises(ValueError, match="register"):
        R.parse_ebpf(struct.pack("<BBhi", 0xB7, 0x0F, 0, 1) + struct.pack("<BBhi", 0x95, 0, 0, 0))
    with pytest.raises(ValueError, match="opcode"):
        R.parse_ebpf(struct.pack("<BBhi", 0xFF, 0, 0, 1) + struct.pack("<BBhi", 0x95, 0, 0, 0))
    # Reserved CALL/EXIT fields are grammar, not ignorable payload bytes.
    with pytest.raises(ValueError, match="EXIT reserved"):
        R.parse_ebpf(struct.pack("<BBhi", 0x95, 1, 0, 0))
    with pytest.raises(ValueError, match="CALL encoding"):
        R.parse_ebpf(struct.pack("<BBhi", 0x85, 1, 0, 1)
                     + struct.pack("<BBhi", 0x95, 0, 0, 0))
    pseudo = (struct.pack("<BBhi", 0x85, 0x10, 0, 0)
              + struct.pack("<BBhi", 0x95, 0, 0, 0))
    parsed = R.parse_ebpf(pseudo)
    assert parsed["helper_calls"] == []
    assert parsed["jump_targets"] == [{"from": 0, "to": 1, "kind": "pseudo_call"}]


def test_packer_requires_independent_evidence_and_never_claims_unpacked_bytes():
    pe = (REPO / "tests/fixtures/mobile_code/Fix.dll").read_bytes()
    one = pe + b"UPX!"
    row = R.packer_evidence(one)[0]
    assert row["kind"] == "UPX-like" and row["confidence"] == "low"
    assert row["review_plan"] == ()
    strong = one + b"UPX0\0UPX1\0"
    row = R.packer_evidence(strong)[0]
    assert row["kind"] == "UPX" and row["confidence"] == "high"
    assert row["verified"] is False and "sandbox" in " ".join(row["review_plan"])
    vmp = pe + b".vmp0\0VMProtect"
    row = R.packer_evidence(vmp)[0]
    assert row["kind"] == "VMProtect" and row["confidence"] == "medium"
    bait = pe + b"VMProtect"
    assert R.packer_evidence(bait)[0]["kind"] == "VMProtect-like"


def test_vm_lifter_checks_unknown_truncation_and_branch_boundaries():
    spec = {"bytecode_hex": "100511fbff", "branch_mode": "relative", "opcode_table": {
        "0x10": {"name": "push", "semantic": "push", "immediate_bytes": 1, "push": 1},
        "0x11": {"name": "jnz", "semantic": "jump_if", "immediate_bytes": 2,
                 "signed": True, "pop": 1},
    }}
    result = R.lift_vm(spec)
    assert result["complete"] is True and result["branch_targets"] == [{"from": 2, "to": 0}]
    assert result["verified"] is False and "supplied opcode table" in result["note"]
    unknown = R.lift_vm({"bytecode_hex": "ff", "opcode_table": {"1": {}}})
    assert unknown["complete"] is False and unknown["unknown"][0]["opcode"] == 255
    with pytest.raises(ValueError, match="past bytecode"):
        R.lift_vm({"bytecode_hex": "10", "opcode_table": {"0x10": {"immediate_bytes": 1}}})
    with pytest.raises(ValueError, match="boundary"):
        R.lift_vm({"bytecode_hex": "11010010ff", "branch_mode": "relative", "opcode_table": {
            "0x11": {"semantic": "jump", "immediate_bytes": 2, "signed": True},
            "0x10": {"immediate_bytes": 1},
        }})
    with pytest.raises(ValueError, match="branch_mode"):
        R.lift_vm({"bytecode_hex": "110000", "opcode_table": {
            "0x11": {"semantic": "jump", "immediate_bytes": 2, "signed": True},
        }})


def test_symbolic_plan_is_source_only_and_review_gated():
    result = R.symbolic_review_plan({"binary": "/chal/check", "mode": "stdin", "length": 4,
                                     "find": [0x401000], "alphabet": "alnum"})
    compile(result["harness"], "<harness>", "exec")
    assert len(result["sha256"]) == 64 and result["candidate_only"] is True
    assert "Docker" in result["run_in"] and "replay" in result["verification"]


def test_toolchain_markers_stay_unverified_and_triage_routes_depth_engine():
    report = R.analyze_languages(b"\x7fELF" + b"\x02\x01" + b"\0" * 20
                                 + b"\xff Go buildinf:\0runtime.main\0")
    go = next(item for item in report["languages"] if item["language"] == "Go")
    assert go["verified"] is False and go["confidence"] == "medium"
    from ctf import triage
    suggestion = triage.suggest("reverse", "VMProtect virtualized eBPF WebAssembly module")
    assert suggestion["engines"][0] == "solvers/toolkits/reverse_formats.py"


def test_guarded_cli_and_5000_seeded_mutations(tmp_path, capsys):
    path = tmp_path / "sample.wasm"
    path.write_bytes(wasm_fixture())
    assert R.main(["wasm", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["verified_structure"] is True
    bad = tmp_path / "bad"
    bad.write_bytes(b"\0asm\1")
    assert R.main(["wasm", str(bad)]) == 2
    assert "Traceback" not in capsys.readouterr().err

    rng = random.Random(0x525635)
    seeds = (wasm_fixture(), ebpf_fixture(), (REPO / "tests/fixtures/mobile_code/Fix.dll").read_bytes())
    parsers = (R.parse_wasm, R.parse_ebpf, R.parse_dotnet_metadata)
    for parser, seed in zip(parsers, seeds):
        for _ in range(5000):
            sample = bytearray(seed)
            for _ in range(1 + rng.randrange(4)):
                if sample and rng.randrange(4) == 0:
                    del sample[rng.randrange(len(sample))]
                elif sample:
                    sample[rng.randrange(len(sample))] ^= 1 << rng.randrange(8)
                else:
                    sample.append(rng.randrange(256))
            try:
                result = parser(bytes(sample))
                assert result.get("verified_structure") is True
            except ValueError:
                pass
    vm_table = {"0x10": {"semantic": "push", "immediate_bytes": 1, "push": 1},
                "0x20": {"semantic": "halt"}}
    for _ in range(5000):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        try:
            result = R.lift_vm({"bytecode_hex": raw.hex(), "opcode_table": vm_table})
            assert len(result["ir"]) <= len(raw)
            assert result["verified"] is False
        except ValueError:
            pass

