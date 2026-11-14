from __future__ import annotations

import base64
import importlib.util
import json
import random
import subprocess
import sys
import time
from types import SimpleNamespace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "solvers" / "toolkits" / "dispatch_crypto.py"
SPEC = importlib.util.spec_from_file_location("r5a_dispatch_crypto_tested", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def candidate(report, value):
    return next(row for row in report["candidates"] if row["value"] == value)


def assert_contract(report):
    assert report["schema"] == "csctf-r5a-autosolve-v1"
    assert report["dispatcher"] == "r5a_crypto"
    assert report["offline"] is True
    assert report["network_requests"] == 0
    assert report["submitted"] is False
    json.dumps(report)
    for row in report["candidates"]:
        assert row["submission_ready"] is False
        assert row["requires_human_review"] is True
        assert row["derivation"]


def test_encoding_chain_exact_flag_and_review_contract():
    wrapped = base64.b64encode(base64.b64encode(b"CSCTF{r5a_chain}"))
    report = MODULE.dispatch("peel this encoding chain", {"layers.txt": wrapped}, category="crypto")
    assert_contract(report)
    row = candidate(report, "CSCTF{r5a_chain}")
    assert row["verified"] is True and row["confidence"] == "high"
    assert report["category"] == "crypto"
    assert any(item["archetype"] == "encoding-chain" and item["status"] == "candidate"
               for item in report["attempts"])


def test_canonical_artifact_identity_survives_autosolve_to_crypto_handoff():
    toolkits = str(PATH.parent)
    if toolkits not in sys.path:
        sys.path.insert(0, toolkits)
    import autosolve

    report = autosolve.autosolve(
        "peel this base64 encoding chain",
        {"layers.txt": base64.b64encode(b"CSCTF{r5a_autosolve_crypto}")},
        category="crypto",
    )
    assert report["dispatcher"] == "autosolve"
    assert report["offline"] and report["network_requests"] == 0 and not report["submitted"]
    assert all(not row["submission_ready"] for row in report["candidates"])
    row = candidate(report, "CSCTF{r5a_autosolve_crypto}")
    assert row["verified"] is True
    dispatched = next(item for item in report["dispatcher_reports"] if item["group"] == "crypto")
    assert dispatched["candidate_count"] >= 1
    assert not any("unsupported artifact" in warning for warning in dispatched["warnings"])


def test_single_byte_xor_replayed_and_unique():
    plaintext = b"CSCTF{r5a_xor}"
    ciphertext = bytes(value ^ 0x42 for value in plaintext)
    report = MODULE.dispatch("single-byte XOR ciphertext; recover the flag", {"cipher.bin": ciphertext})
    assert_contract(report)
    row = candidate(report, plaintext.decode())
    assert row["verified"] is True
    xor = [item for item in report["attempts"] if item["archetype"] == "xor-keystream"]
    assert any(item["status"] == "candidate" and item["key_hex"] == "42" for item in xor)


def test_classical_rot13_has_named_derivation():
    report = MODULE.dispatch("classical ROT13 cipher", {"cipher.txt": b"PFPGS{e5n_pynffvp}"})
    assert_contract(report)
    row = candidate(report, "CSCTF{r5a_classic}")
    assert row["verified"] is True
    attempts = [item for item in report["attempts"] if item["archetype"] == "classical-cipher"]
    assert attempts and attempts[0]["status"] == "candidate"


def test_unstated_classical_guess_is_ranked_but_not_verified():
    report = MODULE.dispatch("mystery letter text", {"cipher.txt": b"PFPGS{hafgngrq_thrff}"})
    assert_contract(report)
    row = candidate(report, "CSCTF{unstated_guess}")
    assert row["verified"] is False
    assert "inferred only" in " ".join(row["derivation"]) or "unstated" in " ".join(row["derivation"])

    generic = MODULE.dispatch("generic classical cipher", {"cipher.txt": b"PFPGS{hafgngrq_thrff}"})
    assert candidate(generic, "CSCTF{unstated_guess}")["verified"] is False


def test_rsa_given_factors_round_trip_to_flag():
    p, q, e = 1_000_000_007, 1_000_000_009, 65_537
    value = b"CTF{x}"
    n = p * q
    ciphertext = pow(int.from_bytes(value, "big"), e, n)
    material = f"n={n}\ne={e}\np={p}\nq={q}\nc={ciphertext}\n".encode()
    report = MODULE.dispatch("RSA weakness: decrypt the ciphertext", {"rsa.txt": material})
    assert_contract(report)
    row = candidate(report, value.decode())
    assert row["verified"] is True and "RSA attack" in " ".join(row["derivation"])
    attempt = next(item for item in report["attempts"] if item["archetype"] == "rsa-weakness"
                   and item["status"] == "candidate")
    assert attempt["attack"] == "given_key"
    assert attempt["factors"] == [str(p), str(q)]


def test_oracles_are_plans_and_never_callbacks_or_network():
    description = "CBC padding oracle plus RSA parity oracle and Bleichenbacher PKCS#1 oracle"
    report = MODULE.dispatch(description, {})
    assert_contract(report)
    plans = [item for item in report["attempts"] if item["status"] == "plan-only"]
    assert {item["archetype"] for item in plans} == {
        "cbc-padding-oracle", "rsa-parity-oracle", "bleichenbacher-oracle",
    }
    assert all(item["network_requests"] == 0 and item["executed"] is False
               and item["candidate_only"] is True for item in plans)
    assert report["candidates"] == []

    hyphenated = MODULE.dispatch("CBC padding-oracle, RSA parity-oracle, and OAEP-oracle", {})
    assert {item["archetype"] for item in hyphenated["attempts"] if item["status"] == "plan-only"} == {
        "cbc-padding-oracle", "rsa-parity-oracle", "manger-oaep-oracle",
    }


def test_xorshift_prediction_is_replayed_but_not_a_flag_candidate():
    state = 123_456_789
    outputs = []
    for _ in range(6):
        outputs.append(state)
        state ^= (state << 13) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        state ^= state >> 17
        state &= 0xFFFFFFFF
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
    report = MODULE.dispatch("predict the xorshift PRNG next output",
                             {"outputs.json": json.dumps(outputs).encode()})
    assert_contract(report)
    row = next(item for item in report["attempts"] if item["engine"] == "xorshift_predict")
    assert row["status"] == "prediction"
    assert row["outcome"] == {
        "next": str(state), "width": 32, "variant": "xorshift32_lrl_13_17_5",
        "verified_transitions": 5, "verified": True,
    }
    assert report["candidates"] == []


def test_ecc_and_hnp_material_declines_without_verified_relation():
    report = MODULE.dispatch("ECC singular curve and ECDSA nonce reuse", {"bad.txt": b"p=17\na=2\nb=3\n"})
    assert_contract(report)
    names = {item["archetype"] for item in report["attempts"]}
    assert {"ecc-weakness", "ecdsa-nonce-reuse", "ecdsa-hidden-number"} <= names
    assert report["candidates"] == []


def test_placeholder_and_competing_raw_flags_are_not_promoted_as_unique():
    report = MODULE.dispatch("decode", {"values.txt": b"CSCTF{...}\nCSCTF{one}\nCSCTF{two}\n"})
    assert_contract(report)
    assert all(row["value"] != "CSCTF{...}" for row in report["candidates"])
    assert all(row["verified"] is False for row in report["candidates"])


def test_invalid_utf8_flag_span_is_declined_and_duplicate_basenames_are_preserved(tmp_path):
    assert MODULE._flag_values(b"CSCTF{\xff}") == []
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir(); right.mkdir()
    (left / "same.txt").write_bytes(base64.b64encode(b"CSCTF{left_path}"))
    (right / "same.txt").write_bytes(base64.b64encode(b"CSCTF{right_path}"))
    report = MODULE.dispatch("encoding chains", [left / "same.txt", right / "same.txt"])
    assert_contract(report)
    assert {row["value"] for row in report["candidates"]} >= {
        "CSCTF{left_path}", "CSCTF{right_path}",
    }


def test_malformed_decoder_provenance_cannot_upgrade_candidate_to_verified():
    crib = SimpleNamespace(
        LAST={"flags": [("CSCTF{provenance}", ("base64",)), object()]},
        solve_blob=lambda *_args, **_kwargs: ("CSCTF{provenance}", [("base64",)], b""),
    )
    attempts, candidates = [], []
    MODULE._encoding_pass(crib, {"layers.txt": b"ignored"}, "base64",
                          time.monotonic() + 1, attempts, candidates)
    assert len(candidates) == 1
    assert candidates[0]["value"] == "CSCTF{provenance}"
    assert candidates[0]["verified"] is False

    for last, answer in (
        ({}, "CSCTF{missing_provenance}"),
        ({"flags": [("CSCTF{one}", ("base64",))]}, "CSCTF{one} CSCTF{two}"),
    ):
        crib = SimpleNamespace(
            LAST=last,
            solve_blob=lambda *_args, _answer=answer, **_kwargs: (_answer, [("base64",)], b""),
        )
        attempts, candidates = [], []
        MODULE._encoding_pass(crib, {"layers.txt": b"ignored"}, "base64",
                              time.monotonic() + 1, attempts, candidates)
        assert candidates and all(row["verified"] is False for row in candidates)


def test_declared_file_cap_is_enforced():
    files = {f"row-{index}.txt": b"" for index in range(MODULE.MAX_FILES + 1)}
    report = MODULE.dispatch("offline crypto review", files)
    assert_contract(report)
    assert len(report["evidence"]) == MODULE.MAX_FILES
    assert any("file cap reached" in note for note in report["ingestion_notes"])


def test_unexpected_engine_and_loader_exceptions_are_contained(monkeypatch):
    def explode(*_args, **_kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(MODULE, "_encoding_pass", explode)
    report = MODULE.dispatch("encoding chain", {})
    assert_contract(report)
    assert any(item["status"] == "declined" and "engine exploded" in item["detail"]
               for item in report["attempts"])

    def stop_loading():
        raise SystemExit("engine requested exit")

    monkeypatch.setattr(MODULE, "_engines", stop_loading)
    report = MODULE.dispatch("crypto", {})
    assert_contract(report)
    assert any(item["status"] == "unavailable" and "engine requested exit" in item["detail"]
               for item in report["attempts"])


def test_bounded_bad_inputs_decline_without_traceback():
    report = MODULE.dispatch("crypto", [("unsupported.bin", object())])
    assert_contract(report)
    assert report["candidates"] == []
    assert report["warnings"]

    too_large = b"A" * (MODULE.MAX_FILE_BYTES + 1)
    report = MODULE.dispatch("base64", {"huge.txt": too_large})
    assert_contract(report)
    assert report["candidates"] == []
    assert report["ingestion_notes"]

    huge_integer = b"[" + b"9" * 5000 + b",1,2]"
    report = MODULE.dispatch("LCG PRNG outputs", {"numbers.txt": huge_integer})
    assert_contract(report)
    assert report["candidates"] == []

    class BrokenMapping(dict):
        def items(self):
            raise RuntimeError("broken mapping")

    report = MODULE.dispatch("crypto", BrokenMapping())
    assert_contract(report)
    assert any("artifact mapping" in warning for warning in report["warnings"])


def test_seeded_mutations_never_escape_and_never_submit():
    rng = random.Random(0xA5C7)
    seeds = [base64.b64encode(b"CSCTF{seed}"), b"n=3233\ne=17\nc=2557\n", b"padding oracle"]
    for _ in range(75):
        data = bytearray(rng.choice(seeds))
        for _ in range(rng.randrange(1, 5)):
            if data:
                data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
        report = MODULE.dispatch("offline crypto review", {"mutated.bin": bytes(data)})
        assert_contract(report)


def test_cli_boundaries_are_guarded(tmp_path):
    no_args = subprocess.run([sys.executable, str(PATH)], cwd=ROOT, text=True,
                             capture_output=True, timeout=10)
    assert no_args.returncode == 2
    assert "Traceback" not in no_args.stderr

    path = tmp_path / "r5a_encoded.txt"
    path.write_bytes(base64.b64encode(b"CSCTF{r5a_cli}"))
    proc = subprocess.run([sys.executable, str(PATH), "--json", "--description", "encoding chain", str(path)],
                          cwd=ROOT, text=True, capture_output=True, timeout=15)
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr
    report = json.loads(proc.stdout)
    assert_contract(report)
    assert candidate(report, "CSCTF{r5a_cli}")["submission_ready"] is False
