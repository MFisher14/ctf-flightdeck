from __future__ import annotations

import importlib.util
import json
import math
import random
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "solvers" / "toolkits" / "dispatch_core.py"
SPEC = importlib.util.spec_from_file_location("r5a_dispatch_core_tested", PATH)
assert SPEC and SPEC.loader
C = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = C
SPEC.loader.exec_module(C)


def test_normalize_artifact_forms_and_public_metadata(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abc")
    rows = C.normalize_artifacts([path, ("memory.txt", b"def"), C.Artifact("x", b"g", "fixture")])
    assert [row.name for row in rows] == ["sample.bin", "memory.txt", "x"]
    assert [row.data for row in rows] == [b"abc", b"def", b"g"]
    assert all(len(row.public()["sha256_read"]) == 64 for row in rows)

    mapped = C.normalize_artifacts({"a.txt": "hello", "b.bin": b"world"})
    assert [(row.name, row.data, row.source) for row in mapped] == [
        ("a.txt", b"hello", "memory"), ("b.bin", b"world", "memory")]
    escaped = C.normalize_artifacts({"evil\x1b[31m.txt": b"x"})[0]
    assert "\x1b" not in escaped.name


def test_normalize_caps_and_invalid_inputs_fail_closed(tmp_path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * 40)
    row = C.normalize_artifacts(path, per_file_cap=16, total_cap=32)[0]
    assert row.data == b"x" * 16 and row.truncated
    with pytest.raises(C.R5AInputError):
        C.normalize_artifacts([("a", b"x" * 20), ("b", b"y" * 20)],
                              per_file_cap=32, total_cap=32)
    with pytest.raises(C.R5AInputError):
        C.normalize_artifacts(tmp_path / "missing")
    with pytest.raises(C.R5AInputError):
        C.normalize_artifacts([object()])


def test_flag_hits_filter_placeholders_and_invalid_utf8():
    blob = (b"CSCTF{...} CSCTF{real_value} CSCTF{real_value} "
            b"CSCTF{\xffbad} CTF{second}")
    assert [row["value"] for row in C.flag_hits(blob)] == ["CSCTF{real_value}", "CTF{second}"]
    assert C.flag_hits("CSCTF{example_flag}") == []
    for placeholder in ("CSCTF{your-flag}", "CSCTF{flag_here}", "CSCTF{example123}",
                        "CSCTF{REDACTED_FLAG}", "CSCTF{replace-me}", "CSCTF{flag123}",
                        "CSCTF{sample123}", "CSCTF{test123}", "CSCTF{redacted123}",
                        "CSCTF{answer}", "CSCTF{value}"):
        assert C.flag_hits(placeholder) == []
    assert C.flag_hits(b"CSCTF{safe\x1b[31mRED}") == []


def test_candidate_contract_and_deterministic_ranking():
    low = C.make_candidate("CSCTF{one}", archetype="x", engine="e1", source="a",
                           derivation=["step"], confidence="low")
    high = C.make_candidate("CSCTF{one}", archetype="x", engine="e2", source="b",
                            derivation=["checked"], evidence=["crc"], verified=True,
                            confidence="high")
    other = C.make_candidate("CSCTF{two}", archetype="x", engine="e3", source="c",
                             derivation=["read"], confidence="medium")
    ranked = C.rank_candidates([low, other, high])
    assert [row["value"] for row in ranked] == ["CSCTF{one}", "CSCTF{two}"]
    assert ranked[0]["verified"] is True and ranked[0]["corroborations"] == 2
    assert ranked[0]["submission_ready"] is False and ranked[0]["requires_human_review"] is True
    with pytest.raises(C.R5AInputError):
        C.make_candidate("CSCTF{...}", archetype="x", engine="e", source="s",
                         derivation=["step"])


def test_duplicate_candidate_cannot_launder_unverified_confidence():
    unverified = C.make_candidate(
        "CSCTF{same}", archetype="guess", engine="untrusted-high", source="a",
        derivation=["shape only"], confidence="high", verified=False)
    verified = C.make_candidate(
        "CSCTF{same}", archetype="decoded", engine="verified-low", source="b",
        derivation=["round-trip checked"], confidence="low", verified=True)
    row = C.rank_candidates([unverified, verified])[0]
    assert row["verified"] is True
    assert row["confidence"] == "low"
    assert row["engine"] == "verified-low" and row["archetype"] == "decoded"
    with pytest.raises(C.R5AInputError):
        C.make_candidate("not-a-flag", archetype="x", engine="e", source="s",
                         derivation=["step"])


def test_safe_engine_boundary_converts_exceptions_and_systemexit():
    def bad():
        raise ValueError("bad\nsecret traceback")

    value, row = C.safe_engine_call("bad", bad)
    assert value is None and row["status"] == "error"
    assert "Traceback" not in json.dumps(row) and "\n" not in row["error"]
    value, row = C.safe_engine_call("exit", lambda: (_ for _ in ()).throw(SystemExit(2)))
    assert value is None and row["status"] == "error"

    class HostileEquality:
        def __eq__(self, _other):
            raise RuntimeError("comparison escaped")

    value, row = C.safe_engine_call("hostile", HostileEquality)
    assert isinstance(value, HostileEquality) and row["status"] == "completed"


def test_caller_constructed_artifact_is_revalidated():
    with pytest.raises(C.R5AInputError):
        C.normalize_artifacts(C.Artifact("bad", "not-bytes", "fixture"))
    normalized = C.normalize_artifacts(C.Artifact("../ok.bin", bytearray(b"ok"), "fixture"))[0]
    assert normalized.name == "ok.bin" and normalized.data == b"ok"


def test_nonfinite_report_values_are_rejected():
    with pytest.raises(C.R5AInputError):
        C.finalize_report({"candidates": [], "bad": math.nan})
    with pytest.raises(ValueError):
        C.public_json({"bad": math.inf})


def test_equal_quality_candidates_are_explicitly_ambiguous():
    rows = C.rank_candidates([
        C.make_candidate("CSCTF{alpha}", archetype="x", engine="e", source="a",
                         derivation=["same"], verified=True, confidence="high"),
        C.make_candidate("CSCTF{beta}", archetype="x", engine="e", source="b",
                         derivation=["same"], verified=True, confidence="high"),
    ])
    assert all(row.get("quality_tie") is True for row in rows)
    assert all("not evidence" in row["rank_reason"] for row in rows)


def test_normalization_stops_after_artifact_cap():
    class EndlessMapping(dict):
        def items(self):
            for index in range(C.MAX_ARTIFACTS + 2):
                yield f"{index}.bin", b"x"

    with pytest.raises(C.R5AInputError, match="too many"):
        C.normalize_artifacts(EndlessMapping())


@pytest.mark.parametrize(("description", "archetype", "dispatcher"), [
    ("peel a base64 encoding chain", "encoding-chain", "crypto"),
    ("reuse XOR keystream with crib drag", "xor-keystream", "crypto"),
    ("Vigenere classical cipher", "classical-cipher", "crypto"),
    ("RSA Wiener weakness", "rsa-ecc", "crypto"),
    ("CBC padding oracle", "crypto-oracle", "crypto"),
    ("predict MT19937 PRNG", "prng", "crypto"),
    ("PNG DCT image stego", "image-stego", "forensics"),
    ("WAV DTMF audio", "audio-stego", "forensics"),
    ("recover a KeePass key from archive", "archive-key-leak", "forensics"),
    ("decode DataMatrix barcode", "qr-barcode", "forensics"),
    ("reconstruct a TCP stream from PCAP", "pcap-network", "forensics"),
    ("Office VBA maldoc macro", "maldoc", "forensics"),
    ("recover QCOW disk image", "disk-forensics", "forensics"),
    ("format string GOT leak then ROP", "pwn-recon", "exploit"),
    ("reverse a PyInstaller binary", "reverse-engineering", "exploit"),
    ("JWT session web trust failure", "web-trust", "exploit"),
    ("Ethereum wallet EVM", "blockchain", "exploit"),
    ("scan SQLite database", "database", "forensics"),
    ("phishing EML metadata", "email-metadata", "forensics"),
    ("UF2 firmware mobile", "firmware-mobile", "forensics"),
    ("Modbus ICS capture", "ics-rf", "forensics"),
])
def test_description_archetype_and_dispatcher_routing(description, archetype, dispatcher):
    rows = C.classify_archetypes(description, [])
    found = next(row for row in rows if row["archetype"] == archetype)
    assert found["score"] >= 4
    groups = C.dispatcher_scores(rows)
    assert next(row for row in groups if row["dispatcher"] == dispatcher)["score"] >= 4


def test_magic_and_unknown_routing():
    artifacts = C.normalize_artifacts({
        "capture.bin": b"\x0a\x0d\x0d\x0a" + b"\0" * 32,
        "doc.bin": b"%PDF-1.7\n",
        "program.bin": b"\x7fELF" + b"\0" * 20,
    })
    names = {row["archetype"] for row in C.classify_archetypes("", artifacts)}
    assert {"pcap-network", "maldoc", "reverse-engineering", "pwn-recon"} <= names
    unknown = C.classify_archetypes("look at this", C.normalize_artifacts({"x": b"?"}))
    assert unknown == [{"archetype": "unknown", "score": 1,
                        "evidence": ["no strong keyword, suffix, or magic signal"]}]
    assert {row["dispatcher"] for row in C.dispatcher_scores(unknown)} == {
        "crypto", "forensics", "exploit"}


def test_punctuation_variants_do_not_mask_cross_lane_signals():
    image = C.normalize_artifacts({"image.png": b"\x89PNG\r\n\x1a\n" + b"x" * 32})
    rows = C.classify_archetypes("PNG containing base-64 text", image)
    assert {row["archetype"] for row in rows} >= {"image-stego", "encoding-chain"}
    audio = C.normalize_artifacts({"audio.wav": b"RIFF\x00\x00\x00\x00WAVE"})
    rows = C.classify_archetypes("audio with a one-time-pad ciphertext", audio)
    assert {row["archetype"] for row in rows} >= {"audio-stego", "xor-keystream"}


def test_direct_scan_unique_conflict_truncation_and_description():
    unique = C.direct_artifact_report("", C.normalize_artifacts({"one.txt": b"x CSCTF{unique} y"}))
    assert unique["candidates"][0]["value"] == "CSCTF{unique}"
    assert unique["candidates"][0]["verified"] is True

    conflict = C.direct_artifact_report("", C.normalize_artifacts({
        "one.txt": b"CSCTF{one}", "two.txt": b"CSCTF{two}"}))
    assert len(conflict["candidates"]) == 2
    assert not any(row["verified"] for row in conflict["candidates"])

    truncated = C.Artifact("part.bin", b"CSCTF{prefix}", "fixture", True)
    report = C.direct_artifact_report("example CSCTF{prose}", [truncated])
    by_value = {row["value"]: row for row in report["candidates"]}
    assert not by_value["CSCTF{prefix}"]["verified"]
    assert not by_value["CSCTF{prose}"]["verified"]
    assert all(row["submission_ready"] is False for row in report["candidates"])


def test_seeded_5000_flag_boundary_cases_never_escape():
    rng = random.Random(0x5A17)
    alphabet = b"CSCTF{}flag0123456789_\x00\xff\r\n"
    for _ in range(5000):
        blob = bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 100)))
        hits = C.flag_hits(blob, source="fuzz")
        assert all(C.FLAG_TEXT_RE.fullmatch(row["value"]) for row in hits)
        assert all(not C.is_placeholder_flag(row["value"]) for row in hits)

