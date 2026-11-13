"""Published-parameter locks for the offline PQC profile auditor.

The expected raw sizes are copied from the parameter tables in FIPS 203,
FIPS 204, and FIPS 205.  They are constants rather than values emitted by the
engine, so the tests cannot bless a size-calculation bug circularly.
"""
from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

import cryptodepth_pqc_audit as audit


FIPS203_SIZES = {
    "ML-KEM-512": (800, 1632, 768, 32),
    "ML-KEM-768": (1184, 2400, 1088, 32),
    "ML-KEM-1024": (1568, 3168, 1568, 32),
}

FIPS204_SIZES = {
    "ML-DSA-44": (1312, 2560, 2420),
    "ML-DSA-65": (1952, 4032, 3309),
    "ML-DSA-87": (2592, 4896, 4627),
}

FIPS205_SIZES = {
    "128s": (32, 64, 7856),
    "128f": (32, 64, 17088),
    "192s": (48, 96, 16224),
    "192f": (48, 96, 35664),
    "256s": (64, 128, 29792),
    "256f": (64, 128, 49856),
}


def _codes(result: audit.PQCAuditResult) -> set[str]:
    return {finding.code for finding in result.findings}


def test_fips203_profiles_match_published_raw_sizes():
    for profile, expected in FIPS203_SIZES.items():
        result = audit.audit_ml_kem(profile)
        assert result is not None
        assert result.classification == "standard"
        assert result.variant == profile
        assert (
            result.sizes.public_key,
            result.sizes.private_key,
            result.sizes.ciphertext,
            result.sizes.shared_secret,
        ) == expected
        assert result.findings == ()


def test_fips204_profiles_match_published_raw_sizes():
    for profile, expected in FIPS204_SIZES.items():
        result = audit.audit_ml_dsa(profile)
        assert result is not None
        assert result.classification == "standard"
        assert result.variant == profile
        assert (
            result.sizes.public_key,
            result.sizes.private_key,
            result.sizes.signature,
        ) == expected
        assert result.findings == ()


def test_all_twelve_fips205_profiles_match_published_raw_sizes():
    for stem, expected in FIPS205_SIZES.items():
        for family in ("SHA2", "SHAKE"):
            profile = f"SLH-DSA-{family}-{stem}"
            result = audit.audit_slh_dsa(profile)
            assert result is not None
            assert result.classification == "standard"
            assert result.variant == profile
            assert (
                result.sizes.public_key,
                result.sizes.private_key,
                result.sizes.signature,
            ) == expected
            assert result.findings == ()


def test_legacy_names_are_not_misreported_as_final_fips_formats():
    kyber = audit.audit_ml_kem("Kyber768")
    dilithium = audit.audit_ml_dsa("Dilithium3")
    sphincs = audit.audit_slh_dsa("SPHINCS+-SHAKE-192s-simple")
    assert kyber is not None and kyber.classification == "legacy"
    assert dilithium is not None and dilithium.classification == "legacy"
    assert sphincs is not None and sphincs.classification == "legacy"
    assert "legacy_variant" in _codes(kyber)
    assert "legacy_variant" in _codes(dilithium)
    assert "legacy_variant" in _codes(sphincs)

    # CRYSTALS-Dilithium round-3 used a 32-byte tr and c-tilde: its published
    # level-3 secret key/signature sizes differ from finalized ML-DSA-65.
    assert (dilithium.sizes.private_key, dilithium.sizes.signature) == (4000, 3293)


def test_valid_small_profiles_are_toy_and_semantic_impossibilities_malformed():
    toy_kem = audit.audit_ml_kem(
        n=128, q=3329, k=1, eta1=2, eta2=2, du=10, dv=4
    )
    toy_dsa = audit.audit_ml_dsa(
        {
            "n": 128,
            "q": 8380417,
            "d": 13,
            "k": 2,
            "l": 2,
            "eta": 2,
            "tau": 20,
            "beta": 40,
            "gamma1": 1 << 17,
            "gamma2": 95232,
            "omega": 20,
            "lambda": 64,
        }
    )
    toy_slh = audit.audit_slh_dsa(
        n=8, h=24, d=3, a=4, k=8, lg_w=4, hash_family="sha2"
    )
    assert toy_kem is not None and toy_kem.classification == "toy"
    assert toy_dsa is not None and toy_dsa.classification == "toy"
    assert toy_slh is not None and toy_slh.classification == "toy"

    malformed_kem = audit.audit_ml_kem(
        n=255, q=3328, k=2, eta1=2, eta2=2, du=10, dv=4
    )
    malformed_dsa = audit.audit_ml_dsa(
        {
            "n": 256,
            "q": 8380417,
            "d": 22,
            "k": 4,
            "l": 4,
            "eta": 2,
            "tau": 300,
            "beta": 78,
            "gamma1": 3,
            "gamma2": 1,
            "omega": 2000,
            "lambda": 129,
        }
    )
    malformed_slh = audit.audit_slh_dsa(
        n=16, h=63, d=8, a=12, k=14, lg_w=4, hash_family="sha2"
    )
    for result in (malformed_kem, malformed_dsa, malformed_slh):
        assert result is not None
        assert result.classification == "malformed"
        assert "malformed_profile" in _codes(result)


def test_explicit_implementation_evidence_produces_specific_findings():
    kem = audit.audit_ml_kem(
        "ML-KEM-768",
        randomness_reused=True,
        implicit_rejection=False,
        modulus_check=False,
        key_hash_check=False,
        oracle_exposed=True,
    )
    dsa = audit.audit_ml_dsa(
        "ML-DSA-65",
        nonce_reuse=True,
        norm_checks=False,
        hint_checks=False,
        side_channel_exposed=True,
    )
    slh = audit.audit_slh_dsa(
        "SLH-DSA-SHAKE-256s",
        address_checks=False,
        root_check=False,
        fault_checks=False,
    )
    assert kem is not None and {
        "randomness_reuse",
        "implicit_rejection_missing",
        "encapsulation_key_check_missing",
        "decapsulation_key_hash_check_missing",
        "decapsulation_oracle",
    } <= _codes(kem)
    assert dsa is not None and {
        "signing_nonce_reuse",
        "norm_checks_missing",
        "hint_checks_missing",
        "side_channel_exposure",
    } <= _codes(dsa)
    assert slh is not None and {
        "address_separation_missing",
        "root_check_missing",
        "fault_checks_missing",
    } <= _codes(slh)


def test_public_contract_is_bounded_fail_closed_and_immutable():
    malformed_calls = (
        (audit.audit_ml_kem, (None,), {}),
        (audit.audit_ml_kem, ("unknown",), {}),
        (audit.audit_ml_kem, (), {"n": True}),
        (audit.audit_ml_dsa, ({"name": "ML-DSA-44", "surprise": 1},), {}),
        (
            audit.audit_ml_kem,
            ({"variant": "ML-KEM-768", "name": "Kyber512"},),
            {},
        ),
        (audit.audit_slh_dsa, (), {"w": 12, "hash_family": "sha2"}),
        (audit.audit_parameters, ({"scheme": object()},), {}),
        (audit.audit_parameters, ("unsupported",), {}),
    )
    for function, args, kwargs in malformed_calls:
        assert function(*args, **kwargs) is None

    compatible_aliases = audit.audit_ml_kem(
        {"algorithm": "FIPS 203", "name": "ML-KEM-768"}
    )
    assert compatible_aliases is not None
    assert compatible_aliases.variant == "ML-KEM-768"

    result = audit.audit_parameters({"scheme": "FIPS 203", "name": "ML-KEM-512"})
    assert result is not None and result.is_standard_profile
    with pytest.raises(FrozenInstanceError):
        result.classification = "toy"
    with pytest.raises(FrozenInstanceError):
        result.sizes.public_key = 1
    with pytest.raises(FrozenInstanceError):
        result.findings = ()


def test_json_cli_and_argparse_systemexit_guard(tmp_path, capsys):
    source = tmp_path / "profile.json"
    source.write_text(
        json.dumps({"scheme": "FIPS 205", "name": "SLH-DSA-SHA2-128s"}),
        encoding="utf-8",
    )
    assert audit.main([str(source)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["classification"] == "standard"
    assert output["sizes"]["signature"] == 7856

    assert audit.main(["--definitely-not-an-option"]) == 2
    assert audit.main([str(tmp_path / "missing.json")]) == 2
    assert audit.main(["--help"]) == 0
