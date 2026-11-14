"""Independent vectors and fail-closed fuzz for the finalized-PQC engines.

The size tables are copied from NIST FIPS 203, 204, and 205.  Raw ML-KEM and
ML-DSA artifacts are produced by ``cryptography`` (OpenSSL's independent
implementation).  The ML-KEM-512 ciphertext is a pinned NIST ACVP vector, and
the SLH-DSA key is NIST ACVP FIPS205 keyGen SHA2-128s, tcId 1.
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

import cryptodepth_pqc as parser
import cryptodepth_pqc_audit as audit


NIST_VECTORS = Path(__file__).with_name("cryptodepth_nist_pqc_vectors.json")

# FIPS 203 Tables 2-4: ek, dk, ciphertext, shared secret.
FIPS203 = {
    "ML-KEM-512": (800, 1632, 768, 32),
    "ML-KEM-768": (1184, 2400, 1088, 32),
    "ML-KEM-1024": (1568, 3168, 1568, 32),
}

# FIPS 204 Table 2: public key, private key, signature.
FIPS204 = {
    "ML-DSA-44": (1312, 2560, 2420),
    "ML-DSA-65": (1952, 4032, 3309),
    "ML-DSA-87": (2592, 4896, 4627),
}

# FIPS 205 parameter sets: public key, private key, signature.  SHA2 and SHAKE
# instantiations have the same raw lengths for a given shape.
FIPS205 = {
    "128s": (32, 64, 7856),
    "128f": (32, 64, 17088),
    "192s": (48, 96, 16224),
    "192f": (48, 96, 35664),
    "256s": (64, 128, 29792),
    "256f": (64, 128, 49856),
}


def _acvp_artifact(name: str, expected_sha256: str) -> bytes:
    fixture = json.loads(NIST_VECTORS.read_text(encoding="utf-8"))["vectors"][name]
    raw = base64.b64decode("".join(fixture["base64_chunks"]), validate=True)
    assert hashlib.sha256(raw).hexdigest() == expected_sha256
    return raw


@pytest.mark.parametrize(
    ("name", "private_type", "seed_byte"),
    [
        ("ML-KEM-768", mlkem.MLKEM768PrivateKey, 0x37),
        ("ML-KEM-1024", mlkem.MLKEM1024PrivateKey, 0xA6),
    ],
)
def test_vector_lock_real_mlkem_objects_from_independent_library(
    name, private_type, seed_byte
):
    secret = private_type.from_seed_bytes(bytes([seed_byte]) * 64)
    public = secret.public_key()
    encoded_public = public.public_bytes_raw()
    shared_secret, ciphertext = public.encapsulate()

    assert len(encoded_public) == FIPS203[name][0]
    assert len(ciphertext) == FIPS203[name][2]
    assert len(shared_secret) == FIPS203[name][3]
    assert secret.decapsulate(ciphertext) == shared_secret

    parsed_public = parser.parse_mlkem(encoded_public, name, "encapsulation_key")
    parsed_ciphertext = parser.parse_mlkem(ciphertext, name, "ciphertext")
    assert parsed_public.fields[-1].name == "rho"
    assert parsed_public.fields[-1].end == len(encoded_public)
    assert parsed_ciphertext.fields[0].name == "c1"
    assert parsed_ciphertext.fields[-1].name == "c2"
    assert parsed_ciphertext.fields[-1].end == len(ciphertext)


def test_vector_lock_nist_acvp_mlkem512_ciphertext():
    ciphertext = _acvp_artifact(
        "ML-KEM-512-ciphertext",
        "081d14f479358be7af78d18d6282832b81d8b7e71faa119571719e1b07b81e4a",
    )
    assert len(ciphertext) == FIPS203["ML-KEM-512"][2]
    parsed = parser.parse_mlkem(ciphertext, "ML-KEM-512", "ciphertext")
    fields = {field.name: (field.offset, field.length, field.end) for field in parsed.fields}
    # FIPS 203: c1 is k*n*du/8 = 2*256*10/8; c2 is n*dv/8.
    assert fields == {"c1": (0, 640, 640), "c2": (640, 128, 768)}


@pytest.mark.parametrize(
    ("name", "private_type", "seed_byte"),
    [
        ("ML-DSA-44", mldsa.MLDSA44PrivateKey, 0x11),
        ("ML-DSA-65", mldsa.MLDSA65PrivateKey, 0x52),
        ("ML-DSA-87", mldsa.MLDSA87PrivateKey, 0xE3),
    ],
)
def test_vector_lock_real_mldsa_objects_from_independent_library(
    name, private_type, seed_byte
):
    secret = private_type.from_seed_bytes(bytes([seed_byte]) * 32)
    public = secret.public_key()
    message = b"CSCTF independent ML-DSA parser oracle"
    signature = secret.sign(message)
    public.verify(signature, message)
    encoded_public = public.public_bytes_raw()

    assert len(encoded_public) == FIPS204[name][0]
    assert len(signature) == FIPS204[name][2]
    parsed_public = parser.parse_mldsa(encoded_public, name, "public_key")
    parsed_signature = parser.parse_mldsa(signature, name, "signature")
    assert parsed_public.fields[0].name == "rho"
    assert parsed_public.fields[-1].end == len(encoded_public)
    assert parsed_signature.fields[0].name == "c_tilde"
    assert parsed_signature.fields[-1].name == "hint_endpoints"
    assert parsed_signature.fields[-1].end == len(signature)


def test_vector_lock_nist_acvp_slhdsa_key_and_published_sizes():
    public_key = bytes.fromhex(
        "0D794777914C99766827F0F09CA972BE"
        "0162C10219D422ADBA1359E6AA65299C"
    )
    private_key = bytes.fromhex(
        "173D04C938C1C36BF289C3C022D04B14"
        "63AE23C41AA546DA589774AC20B745C4"
        "0D794777914C99766827F0F09CA972BE"
        "0162C10219D422ADBA1359E6AA65299C"
    )
    assert hashlib.sha256(public_key).hexdigest() == (
        "e7484e41b32f205939f202c3a29a72a1d43118f5ffc588323f81bf5b547c7b43"
    )
    assert hashlib.sha256(private_key).hexdigest() == (
        "9087eb86d94a35bb52afc858b1e95d03a5c581b9321eb4ef7b56919c50b26f5b"
    )
    parsed_public = parser.parse_slhdsa(public_key, "SLH-DSA-SHA2-128s", "public_key")
    parsed_private = parser.parse_slhdsa(private_key, "SLH-DSA-SHA2-128s", "private_key")
    assert [(item.name, item.offset, item.length) for item in parsed_public.fields] == [
        ("pk_seed", 0, 16),
        ("pk_root", 16, 16),
    ]
    assert [item.name for item in parsed_private.fields] == [
        "sk_seed", "sk_prf", "pk_seed", "pk_root"
    ]
    assert parsed_private.fields[-1].end == 64

    for shape, expected in FIPS205.items():
        for hash_family in ("SHA2", "SHAKE"):
            result = audit.audit_slh_dsa(f"SLH-DSA-{hash_family}-{shape}")
            assert result is not None and result.classification == "standard"
            assert (result.sizes.public_key, result.sizes.private_key, result.sizes.signature) == expected


def test_vector_lock_fips_size_tables_in_parameter_auditor():
    for name, expected in FIPS203.items():
        result = audit.audit_ml_kem(name)
        assert result is not None and result.classification == "standard"
        assert (
            result.sizes.public_key,
            result.sizes.private_key,
            result.sizes.ciphertext,
            result.sizes.shared_secret,
        ) == expected
    for name, expected in FIPS204.items():
        result = audit.audit_ml_dsa(name)
        assert result is not None and result.classification == "standard"
        assert (
            result.sizes.public_key,
            result.sizes.private_key,
            result.sizes.signature,
        ) == expected


RAW_PARSER_CASES = (
    (parser.parse_mlkem, ("ML-KEM-512", "encapsulation_key"), bytes(800)),
    (parser.parse_mldsa, ("ML-DSA-44", "signature"), bytes(2420)),
    (parser.parse_slhdsa, ("SLH-DSA-SHA2-128s", "public_key"), bytes(32)),
)


@pytest.mark.parametrize(("function", "arguments", "valid"), RAW_PARSER_CASES)
def test_fail_closed_raw_parser_truncation_bitflips_random_and_oversize(
    function, arguments, valid
):
    rng = random.Random(0xDBAC)
    bit_flipped = bytearray(valid)
    bit_flipped[len(bit_flipped) // 2] ^= 0x80
    maybe_valid = [bytes(bit_flipped), bytes(rng.randrange(256) for _ in range(len(valid)))]

    for malformed in (b"", valid[:1], valid[: len(valid) // 2], valid[:-1], bytes(17)):
        with pytest.raises(parser.PQCParseError):
            function(malformed, *arguments)
    with pytest.raises(parser.PQCParseError):
        function(bytes(parser.MAX_OBJECT_BYTES + 1), *arguments)

    # A same-length mutation can remain structurally valid.  It may return or
    # reject, but no implementation exception may cross the public boundary.
    for mutated in maybe_valid:
        try:
            function(mutated, *arguments)
        except parser.PQCParseError:
            pass
        except Exception as exc:  # pragma: no cover - assertion explains a leak
            pytest.fail(f"stdlib exception escaped {function.__name__}: {type(exc).__name__}")


@pytest.mark.parametrize(
    "bad_value",
    [None, 0, -1, 1.5, "bytes", [], {}, object()],
)
def test_fail_closed_raw_parser_type_fuzz_uses_only_declared_error(bad_value):
    calls = (
        (parser.parse_mlkem, (bad_value, "ML-KEM-512", "encapsulation_key")),
        (parser.parse_mldsa, (bad_value, "ML-DSA-44", "signature")),
        (parser.parse_slhdsa, (bad_value, "SLH-DSA-SHA2-128s", "public_key")),
        (parser.parse_pqc, (bad_value, "ML-KEM", "ML-KEM-512", "ciphertext")),
    )
    for function, arguments in calls:
        with pytest.raises(parser.PQCParseError):
            function(*arguments)
        assert parser.identify_pqc(bad_value) == ()


def test_fail_closed_parameter_auditor_fuzz_never_raises():
    oversized_mapping = {f"field-{index}": index for index in range(audit.MAX_FIELDS + 1)}
    invalid = (
        None,
        b"",
        b"\x00\xffrandom",
        "",
        "ML-K",
        {},
        {"scheme": "ML-KEM"},
        {"scheme": "ML-KEM", "name": "X" * (audit.MAX_LABEL_LENGTH + 1)},
        {"scheme": "ML-KEM", "n": 1 << 100},
        oversized_mapping,
    )
    functions = (audit.audit_ml_kem, audit.audit_ml_dsa, audit.audit_slh_dsa, audit.audit_parameters)
    for value in invalid:
        for function in functions:
            try:
                result = function(value)
            except Exception as exc:  # pragma: no cover - assertion explains a leak
                pytest.fail(f"exception escaped {function.__name__}: {type(exc).__name__}")
            assert result is None

    # Bit-flipped numeric evidence may describe a toy/nonstandard profile, but
    # the public audit boundary must still return cleanly.
    profile = {
        "n": 256,
        "q": 3329 ^ 1,
        "k": 2,
        "eta1": 3,
        "eta2": 2,
        "du": 10,
        "dv": 4,
    }
    result = audit.audit_ml_kem(profile)
    assert result is None or result.classification in {
        "toy", "nonstandard", "malformed", "standard", "legacy"
    }


def test_fail_closed_audit_json_cli_empty_random_truncated_and_oversized(tmp_path):
    cases = {
        "empty.json": b"",
        "random.json": bytes(random.Random(0xF1F5).randrange(256) for _ in range(128)),
        "truncated.json": b'{"scheme":"ML-KEM","name":"ML-KEM-768"',
        "bitflip.json": b'{"scheme":"ML-KEN","name":"ML-KEM-768"}',
        "oversized.json": b" " * (audit.MAX_JSON_BYTES + 1),
    }
    for name, data in cases.items():
        path = tmp_path / name
        path.write_bytes(data)
        assert audit.main([str(path)]) == 2
