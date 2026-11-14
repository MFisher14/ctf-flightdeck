"""Finalized-PQC parser tests with NIST ACVP vectors and independent layouts.

The public-key seeds and SHA-256 commitments below are from the official NIST
ACVP Server ``internalProjection.json`` files for FIPS 203 and FIPS 204.  The
``cryptography`` implementation derives the real keys independently; the
parser never implements key generation.  FIPS 205 key bytes are copied from
the official SLH-DSA keyGen vector.  Synthetic signatures use a small,
test-local reference layout because a raw SLH-DSA signature has no canonical
integer encoding beyond its published fixed field lengths.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

import cryptodepth_pqc as pqc


NIST_VECTOR_FILE = Path(__file__).with_name("cryptodepth_nist_pqc_vectors.json")


def _nist_artifact(name: str) -> bytes:
    """Load one pinned official ACVP artifact and verify its commitment."""

    fixture = json.loads(NIST_VECTOR_FILE.read_text(encoding="utf-8"))["vectors"][name]
    raw = base64.b64decode("".join(fixture["base64_chunks"]), validate=True)
    assert hashlib.sha256(raw).hexdigest() == fixture["sha256"]
    return raw


MLKEM_ACVP = {
    "ML-KEM-768": (
        mlkem.MLKEM768PrivateKey,
        "E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0"
        "1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0",
        "4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e",
    ),
    "ML-KEM-1024": (
        mlkem.MLKEM1024PrivateKey,
        "F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009"
        "35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275",
        "b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6",
    ),
}

MLDSA_ACVP = {
    "ML-DSA-44": (
        mldsa.MLDSA44PrivateKey,
        "7194B13C95231010AFD2C909992BD2003BA6F437C3886BDBE3F6B867A14BA161",
        "838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03",
    ),
    "ML-DSA-65": (
        mldsa.MLDSA65PrivateKey,
        "A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8",
        "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a",
    ),
    "ML-DSA-87": (
        mldsa.MLDSA87PrivateKey,
        "A16F5B0796703E2D1A0140A35CBF36EFABE70E752BA59B6A9A0E9C4B05302F73",
        "33f49649f05ec2fc3b050007b18ade043bbc8d1c0ded03a269d540486daaa5f4",
    ),
}

MLKEM_LAYOUTS = {
    "ML-KEM-512": (2, 800, 1632, 768, 10, 4),
    "ML-KEM-768": (3, 1184, 2400, 1088, 10, 4),
    "ML-KEM-1024": (4, 1568, 3168, 1568, 11, 5),
}

MLDSA_LAYOUTS = {
    "ML-DSA-44": (4, 4, 2, 128, 80, 1312, 2560, 2420, 576),
    "ML-DSA-65": (6, 5, 4, 192, 55, 1952, 4032, 3309, 640),
    "ML-DSA-87": (8, 7, 2, 256, 75, 2592, 4896, 4627, 640),
}

SLH_LAYOUTS = {
    "128s": (16, 63, 7, 12, 14, 7856),
    "128f": (16, 66, 22, 6, 33, 17088),
    "192s": (24, 63, 7, 14, 17, 16224),
    "192f": (24, 66, 22, 8, 33, 35664),
    "256s": (32, 64, 8, 14, 22, 29792),
    "256f": (32, 68, 17, 9, 35, 49856),
}


def _params(parsed):
    return dict(parsed.parameters)


def _field_map(parsed):
    return {field.name: (field.offset, field.length, field.end) for field in parsed.fields}


def _reference_wots_len(n: int, w: int = 16) -> int:
    """Direct FIPS 205 definition, independent of the engine implementation."""

    log_w = w.bit_length() - 1
    length_1 = (8 * n + log_w - 1) // log_w
    value = length_1 * (w - 1)
    length_2 = 0
    while value:
        length_2 += 1
        value //= w
    return length_1 + length_2


def test_nist_acvp_mlkem_public_keys_and_1568_byte_ambiguity():
    for parameter_set, (private_cls, seed_hex, digest_hex) in MLKEM_ACVP.items():
        public = private_cls.from_seed_bytes(bytes.fromhex(seed_hex)).public_key().public_bytes_raw()
        assert hashlib.sha256(public).hexdigest() == digest_hex
        parsed = pqc.parse_mlkem(public, parameter_set, "encapsulation_key")
        assert parsed.standard == "FIPS 203"
        assert parsed.parameter_set == parameter_set
        assert parsed.length == MLKEM_LAYOUTS[parameter_set][1]
        assert parsed.fields[-1].name == "rho" and parsed.fields[-1].length == 32

    ek_1024 = mlkem.MLKEM1024PrivateKey.from_seed_bytes(
        bytes.fromhex(MLKEM_ACVP["ML-KEM-1024"][1])
    ).public_key().public_bytes_raw()
    matches = pqc.identify_pqc(
        ek_1024, families="ml-kem", parameter_sets="ML-KEM-1024"
    )
    assert {item.kind for item in matches} == {"encapsulation_key", "ciphertext"}
    assert all(item.length == 1568 for item in matches)


def test_mlkem_all_fips_layouts_hash_check_and_canonicality():
    for parameter_set, (k, ek_len, dk_len, ct_len, du, dv) in MLKEM_LAYOUTS.items():
        ek = bytes(ek_len)  # 12-bit coefficient zero is a canonical reference encoding.
        parsed_ek = pqc.parse_mlkem(ek, parameter_set, "ek")
        assert parsed_ek.length == ek_len
        assert len([field for field in parsed_ek.fields if field.name.startswith("t_hat")]) == k

        dk_pke = bytes(384 * k)
        dk = dk_pke + ek + hashlib.sha3_256(ek).digest() + bytes([0xA5]) * 32
        assert len(dk) == dk_len
        parsed_dk = pqc.parse_mlkem(dk, parameter_set, "dk")
        assert _field_map(parsed_dk)["embedded_ek"] == (384 * k, ek_len, 384 * k + ek_len)
        assert _field_map(parsed_dk)["z"][2] == dk_len

        bad_hash = bytearray(dk)
        bad_hash[-33] ^= 1
        with pytest.raises(pqc.PQCParseError):
            pqc.parse_mlkem(bad_hash, parameter_set, "decapsulation_key")

        ciphertext = bytes(ct_len)
        parsed_ct = pqc.parse_mlkem(ciphertext, parameter_set, "ct")
        assert _field_map(parsed_ct)["c1"] == (0, 32 * du * k, 32 * du * k)
        assert _field_map(parsed_ct)["c2"] == (32 * du * k, 32 * dv, ct_len)

        noncanonical = bytearray(ek)
        noncanonical[0] = 0xFF
        noncanonical[1] = (noncanonical[1] & 0xF0) | 0x0F  # coefficient 0 = 4095
        with pytest.raises(pqc.PQCParseError):
            pqc.parse_mlkem(noncanonical, parameter_set, "encapsulation_key")


def test_nist_acvp_mlkem_ciphertexts_are_accepted_as_real_encodings():
    for parameter_set, (_, _, _, ciphertext_len, _, _) in MLKEM_LAYOUTS.items():
        ciphertext = _nist_artifact(f"{parameter_set}-ciphertext")
        assert len(ciphertext) == ciphertext_len
        parsed = pqc.parse_mlkem(ciphertext, parameter_set, "ciphertext")
        assert parsed.standard == "FIPS 203"
        assert parsed.fields[-1].end == ciphertext_len


def test_nist_acvp_mldsa_public_keys_and_all_fips_layouts():
    for parameter_set, (private_cls, seed_hex, digest_hex) in MLDSA_ACVP.items():
        public = private_cls.from_seed_bytes(bytes.fromhex(seed_hex)).public_key().public_bytes_raw()
        assert hashlib.sha256(public).hexdigest() == digest_hex
        parsed = pqc.parse_mldsa(public, parameter_set, "public_key")
        k, _, _, _, _, pk_len, _, _, _ = MLDSA_LAYOUTS[parameter_set]
        assert parsed.length == pk_len
        assert len([field for field in parsed.fields if field.name.startswith("t1[")]) == k

    for parameter_set, layout in MLDSA_LAYOUTS.items():
        k, ell, eta, lambda_bits, omega, _, sk_len, sig_len, z_poly_len = layout
        secret_key = bytes(sk_len)
        parsed_sk = pqc.parse_mldsa(secret_key, parameter_set, "private_key")
        assert len([field for field in parsed_sk.fields if field.name.startswith("s1[")]) == ell
        assert len([field for field in parsed_sk.fields if field.name.startswith("s2[")]) == k
        assert parsed_sk.fields[-1].end == sk_len

        bad_secret = bytearray(secret_key)
        bad_secret[128] = 0xFF  # first eta-packed symbol is 7 or 15, both invalid.
        with pytest.raises(pqc.PQCParseError):
            pqc.parse_mldsa(bad_secret, parameter_set, "private_key")

        signature = bytes(sig_len)
        parsed_sig = pqc.parse_mldsa(signature, parameter_set, "signature")
        fields = _field_map(parsed_sig)
        assert fields["c_tilde"] == (0, lambda_bits // 4, lambda_bits // 4)
        assert fields[f"z[{ell - 1}]"][1] == z_poly_len
        assert fields["hint_indices"][1] == omega
        assert fields["hint_endpoints"][1] == k
        assert parsed_sig.fields[-1].end == sig_len


def test_nist_acvp_mldsa_signatures_are_accepted_as_real_encodings():
    for parameter_set, (_, _, _, _, _, _, _, signature_len, _) in MLDSA_LAYOUTS.items():
        signature = _nist_artifact(f"{parameter_set}-signature")
        assert len(signature) == signature_len
        parsed = pqc.parse_mldsa(signature, parameter_set, "signature")
        assert parsed.standard == "FIPS 204"
        assert "canonical_hint_encoding" in parsed.checks


def test_mldsa_hint_decoder_rejects_each_noncanonical_form():
    _, ell, _, lambda_bits, omega, _, _, sig_len, z_poly_len = MLDSA_LAYOUTS["ML-DSA-44"]
    hint_offset = lambda_bits // 4 + ell * z_poly_len

    decreasing = bytearray(sig_len)
    decreasing[hint_offset] = 3
    decreasing[hint_offset + 1] = 4
    decreasing[hint_offset + omega] = 2
    decreasing[hint_offset + omega + 1] = 1

    duplicate = bytearray(sig_len)
    duplicate[hint_offset] = 7
    duplicate[hint_offset + 1] = 7
    duplicate[hint_offset + omega] = 2

    excessive = bytearray(sig_len)
    excessive[hint_offset + omega] = omega + 1

    padded = bytearray(sig_len)
    padded[hint_offset + omega - 1] = 1

    for malformed in (decreasing, duplicate, excessive, padded):
        with pytest.raises(pqc.PQCParseError):
            pqc.parse_mldsa(malformed, "ML-DSA-44", "signature")


def test_nist_acvp_slhdsa_key_and_independent_signature_boundaries():
    # NIST ACVP SLH-DSA keyGen FIPS205, SHA2-128s, tcId 1.
    public_key = bytes.fromhex(
        "0D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C"
    )
    private_key = bytes.fromhex(
        "173D04C938C1C36BF289C3C022D04B14"
        "63AE23C41AA546DA589774AC20B745C4"
        "0D794777914C99766827F0F09CA972BE"
        "0162C10219D422ADBA1359E6AA65299C"
    )
    parsed_pk = pqc.parse_slhdsa(public_key, "SLH-DSA-SHA2-128s", "public_key")
    parsed_sk = pqc.parse_slhdsa(private_key, "SLH-DSA-SHA2-128s", "private_key")
    assert parsed_pk.fields[0].length == 16 and parsed_pk.fields[-1].end == 32
    assert parsed_sk.fields[2].offset == 32 and parsed_sk.fields[-1].end == 64

    # Raw bytes cannot distinguish SHA2/SHAKE or s/f when key sizes collide.
    pk_matches = pqc.identify_pqc(public_key, families="slh-dsa", kinds="public_key")
    assert {item.parameter_set for item in pk_matches} == {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
    }
    all_sk_matches = pqc.identify_pqc(private_key, families="slh-dsa")
    assert len(all_sk_matches) == 8  # four 128-bit private and four 256-bit public profiles

    for stem, (n, h, d, a, k, signature_len) in SLH_LAYOUTS.items():
        wots_len = _reference_wots_len(n)
        fors_len = k * (a + 1) * n
        ht_len = (h + d * wots_len) * n
        signature = bytes([0x11]) * n + bytes([0x22]) * fors_len + bytes([0x33]) * ht_len
        assert len(signature) == signature_len
        for hash_family in ("SHA2", "SHAKE"):
            parameter_set = f"SLH-DSA-{hash_family}-{stem}"
            parsed = pqc.parse_slhdsa(signature, parameter_set, "signature")
            assert _field_map(parsed) == {
                "R": (0, n, n),
                "FORS": (n, fors_len, n + fors_len),
                "HT": (n + fors_len, ht_len, signature_len),
            }
            assert _params(parsed)["wots_len"] == wots_len


def test_declared_error_contract_identifier_and_immutability():
    strict_calls = (
        (pqc.parse_mlkem, (None, "ML-KEM-512", "ek")),
        (pqc.parse_mlkem, (b"x", object(), "ek")),
        (pqc.parse_mldsa, ("not bytes", "ML-DSA-44", "signature")),
        (pqc.parse_slhdsa, ([0] * 32, "SLH-DSA-SHA2-128s", "public_key")),
        (pqc.parse_pqc, (bytes(32), "unknown", "x", "public_key")),
    )
    for function, arguments in strict_calls:
        with pytest.raises(pqc.PQCParseError):
            function(*arguments)

    for malformed in (None, 1, "text", [0], object(), b"", bytes(pqc.MAX_OBJECT_BYTES + 1)):
        assert pqc.identify_pqc(malformed) == ()

    parsed = pqc.parse_mlkem(bytes(800), "ML-KEM-512", "ek")
    with pytest.raises(FrozenInstanceError):
        parsed.length = 1
    with pytest.raises(FrozenInstanceError):
        parsed.fields[0].offset = 1


def test_parser_cli_json_and_argparse_guard(tmp_path, capsys):
    path = tmp_path / "mlkem1024.bin"
    path.write_bytes(bytes(1568))
    assert pqc.main([
        str(path), "--family", "ml-kem", "--parameter-set", "ML-KEM-1024", "--json"
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ambiguous"] is True
    assert {item["kind"] for item in output["matches"]} == {"encapsulation_key", "ciphertext"}

    assert pqc.main(["--definitely-not-an-option"]) == 2
    assert pqc.main([str(tmp_path / "missing.bin")]) == 2

