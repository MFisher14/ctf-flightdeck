"""Bounded, offline parameter-profile audits for finalized and toy PQC.

The module recognizes the raw parameter profiles standardized by FIPS 203
(ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA), derives their raw
artifact sizes algebraically, and highlights common CTF-grade weak or broken
variants.  Explicit legacy Kyber, Dilithium, and SPHINCS+ labels are kept
separate: matching dimensions do *not* make their byte formats compatible with
the finalized standards.

This is an analysis helper, not a cryptographic validator.  In particular, an
empty ``findings`` tuple and a ``standard`` parameter classification make no
claim about an implementation, key, signature, side-channel resistance, or
operational safety.  No network access or untrusted-code execution is used.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any


MAX_FIELDS = 64
MAX_LABEL_LENGTH = 128
MAX_INTEGER = (1 << 63) - 1
MAX_DIMENSION = 65_536
MAX_SMALL_PARAMETER = 4_096
MAX_ENCODING_BYTES = 4_096
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024


class PQCAuditError(Exception):
    """The sole exception type used by internal strict audit operations."""


@dataclass(frozen=True, slots=True)
class PQCAuditFinding:
    """One bounded parameter or operational concern."""

    code: str
    severity: str
    detail: str


@dataclass(frozen=True, slots=True)
class PQCArtifactSizes:
    """Algebraically derived raw artifact lengths, in bytes."""

    public_key: int | None = None
    private_key: int | None = None
    ciphertext: int | None = None
    signature: int | None = None
    shared_secret: int | None = None
    components: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class PQCAuditResult:
    """Immutable profile audit.

    ``classification`` is one of ``standard``, ``legacy``, ``toy``,
    ``nonstandard``, or ``malformed``.  It classifies the supplied parameter
    profile, not the security of an implementation.
    """

    scheme: str
    classification: str
    variant: str | None
    parameters: tuple[tuple[str, int | str | bool], ...]
    sizes: PQCArtifactSizes
    findings: tuple[PQCAuditFinding, ...]

    @property
    def is_standard_profile(self) -> bool:
        """Whether the numeric and raw-encoding profile exactly matches FIPS."""

        return self.classification == "standard"


_ML_KEM_PROFILES: dict[str, dict[str, int]] = {
    "ML-KEM-512": {
        "n": 256,
        "q": 3329,
        "k": 2,
        "eta1": 3,
        "eta2": 2,
        "du": 10,
        "dv": 4,
    },
    "ML-KEM-768": {
        "n": 256,
        "q": 3329,
        "k": 3,
        "eta1": 2,
        "eta2": 2,
        "du": 10,
        "dv": 4,
    },
    "ML-KEM-1024": {
        "n": 256,
        "q": 3329,
        "k": 4,
        "eta1": 2,
        "eta2": 2,
        "du": 11,
        "dv": 5,
    },
}

_ML_DSA_PROFILES: dict[str, dict[str, int]] = {
    "ML-DSA-44": {
        "n": 256,
        "q": 8_380_417,
        "d": 13,
        "k": 4,
        "l": 4,
        "eta": 2,
        "tau": 39,
        "beta": 78,
        "gamma1": 1 << 17,
        "gamma2": 95_232,
        "omega": 80,
        "lambda": 128,
    },
    "ML-DSA-65": {
        "n": 256,
        "q": 8_380_417,
        "d": 13,
        "k": 6,
        "l": 5,
        "eta": 4,
        "tau": 49,
        "beta": 196,
        "gamma1": 1 << 19,
        "gamma2": 261_888,
        "omega": 55,
        "lambda": 192,
    },
    "ML-DSA-87": {
        "n": 256,
        "q": 8_380_417,
        "d": 13,
        "k": 8,
        "l": 7,
        "eta": 2,
        "tau": 60,
        "beta": 120,
        "gamma1": 1 << 19,
        "gamma2": 261_888,
        "omega": 75,
        "lambda": 256,
    },
}

# The six structural profiles apply to both SHA-2 and SHAKE instantiations.
_SLH_SHAPES: dict[str, dict[str, int]] = {
    "128s": {"n": 16, "h": 63, "d": 7, "a": 12, "k": 14, "lg_w": 4},
    "128f": {"n": 16, "h": 66, "d": 22, "a": 6, "k": 33, "lg_w": 4},
    "192s": {"n": 24, "h": 63, "d": 7, "a": 14, "k": 17, "lg_w": 4},
    "192f": {"n": 24, "h": 66, "d": 22, "a": 8, "k": 33, "lg_w": 4},
    "256s": {"n": 32, "h": 64, "d": 8, "a": 14, "k": 22, "lg_w": 4},
    "256f": {"n": 32, "h": 68, "d": 17, "a": 9, "k": 35, "lg_w": 4},
}


_COMMON_LABEL_FIELDS = {"scheme", "name", "variant", "algorithm"}
_ML_KEM_INTEGER_FIELDS = {
    "n",
    "q",
    "k",
    "eta1",
    "eta2",
    "du",
    "dv",
    "coeff_bits",
    "rho_bytes",
    "hash_bytes",
    "z_bytes",
    "shared_secret_bytes",
}
_ML_KEM_BOOLEAN_FIELDS = {
    "reuse",
    "randomness_reused",
    "coins_reused",
    "implicit_rejection",
    "modulus_check",
    "key_hash_check",
    "domain_separation",
    "constant_time",
    "oracle_exposed",
}
_ML_DSA_INTEGER_FIELDS = {
    "n",
    "q",
    "d",
    "k",
    "l",
    "eta",
    "tau",
    "beta",
    "gamma1",
    "gamma2",
    "omega",
    "lambda",
    "rho_bytes",
    "key_bytes",
    "tr_bytes",
    "challenge_bytes",
    "hint_index_bytes",
    "hint_count_bytes",
}
_ML_DSA_BOOLEAN_FIELDS = {
    "reuse",
    "randomness_reused",
    "nonce_reuse",
    "norm_checks",
    "hint_checks",
    "domain_separation",
    "constant_time",
    "hedged_signing",
    "side_channel_exposed",
}
_SLH_INTEGER_FIELDS = {"n", "h", "d", "a", "k", "lg_w", "w"}
_SLH_STRING_FIELDS = {"hash_family"}
_SLH_BOOLEAN_FIELDS = {
    "reuse",
    "randomness_reused",
    "address_checks",
    "address_domain_separation",
    "domain_separation",
    "root_check",
    "context_binding",
    "constant_time",
    "fault_checks",
}


def _ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0 or denominator <= 0:
        raise PQCAuditError("invalid size expression")
    return (numerator + denominator - 1) // denominator


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _is_prime_64(value: int) -> bool:
    """Deterministic Miller-Rabin for the bounded 64-bit input domain."""

    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False
    odd = value - 1
    shifts = 0
    while odd % 2 == 0:
        odd //= 2
        shifts += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % value == 0:
            continue
        witness = pow(base, odd, value)
        if witness in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def _token(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def _bounded_label(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise PQCAuditError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text) > MAX_LABEL_LENGTH:
        raise PQCAuditError(f"{field} is empty or too long")
    return text


def _exact_int(value: Any, field: str, *, maximum: int = MAX_INTEGER) -> int:
    if isinstance(value, bool):
        raise PQCAuditError(f"{field} must be an integer, not boolean")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        text = value.strip().lower()
        try:
            if text.startswith(("0x", "+0x", "-0x")):
                result = int(text, 16)
            else:
                result = int(text, 10)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PQCAuditError(f"{field} is not an exact integer") from exc
    else:
        raise PQCAuditError(f"{field} must be an exact integer")
    if result <= 0 or result > maximum:
        raise PQCAuditError(f"{field} is outside the supported range")
    return result


def _optional_bool(data: Mapping[str, Any], *fields: str) -> bool | None:
    values: list[bool] = []
    for field in fields:
        if field not in data:
            continue
        value = data[field]
        if not isinstance(value, bool):
            raise PQCAuditError(f"{field} must be boolean")
        values.append(value)
    if not values:
        return None
    if any(value != values[0] for value in values[1:]):
        raise PQCAuditError(f"conflicting aliases: {', '.join(fields)}")
    return values[0]


def _checked_size(value: int, field: str) -> int:
    if not isinstance(value, int) or value < 0 or value > MAX_ARTIFACT_BYTES:
        raise PQCAuditError(f"derived {field} size exceeds the analysis cap")
    return value


def _copy_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    if len(args) > 1:
        raise PQCAuditError("pass at most one mapping or profile name")
    data: dict[str, Any] = {}
    if args:
        source = args[0]
        if isinstance(source, str):
            data["name"] = source
        elif isinstance(source, Mapping):
            if len(source) > MAX_FIELDS:
                raise PQCAuditError("too many parameter fields")
            for key, value in source.items():
                if not isinstance(key, str) or not key or len(key) > MAX_LABEL_LENGTH:
                    raise PQCAuditError("parameter keys must be short strings")
                data[key] = value
        else:
            raise PQCAuditError("parameters must be supplied as a mapping")
    if len(data) + len(kwargs) > MAX_FIELDS:
        raise PQCAuditError("too many parameter fields")
    for key, value in kwargs.items():
        if key in data:
            raise PQCAuditError(f"duplicate parameter field: {key}")
        data[key] = value
    return data


def _reject_unknown(data: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PQCAuditError(f"unknown parameter field: {unknown[0]}")


def _profile_label(
    data: Mapping[str, Any],
    resolver,
    generic_tokens: set[str],
) -> str | None:
    """Return one consistent profile label from its accepted aliases.

    ``algorithm`` is often a generic finalized-family label next to a more
    specific ``name`` or ``variant``.  Those generic labels are compatible;
    two distinct parameter-set/legacy meanings are not.  Rejecting conflicts
    prevents a caller-controlled key order from silently selecting a profile.
    """

    labels: list[tuple[str, str]] = []
    for field in ("variant", "name", "algorithm"):
        if field in data:
            labels.append((field, _bounded_label(data[field], field)))
    if not labels:
        return None

    specific = [item for item in labels if _token(item[1]) not in generic_tokens]
    compared = specific if specific else labels
    identities: set[tuple[str, str]] = set()
    for _field, text in compared:
        resolved = resolver(text)
        profile, variant, kind = resolved[:3]
        if profile is None:
            identities.add(("unknown", _token(text)))
        else:
            identities.add((kind, str(variant)))
    if len(identities) != 1:
        raise PQCAuditError("conflicting profile label aliases")
    return compared[0][1]


def _fill_missing(data: dict[str, Any], profile: Mapping[str, int] | None) -> None:
    if profile is None:
        return
    for field, value in profile.items():
        data.setdefault(field, value)


def _finding(
    findings: list[PQCAuditFinding], code: str, severity: str, detail: str
) -> None:
    if any(existing.code == code for existing in findings):
        return
    findings.append(PQCAuditFinding(code, severity, detail))


def _freeze_parameters(data: Mapping[str, Any], fields: set[str]) -> tuple[tuple[str, Any], ...]:
    frozen = []
    for field in sorted(fields):
        if field not in data:
            continue
        value = data[field]
        if isinstance(value, (bool, int, str)):
            frozen.append((field, value))
    return tuple(frozen)


def _matching_profile(
    values: Mapping[str, int], profiles: Mapping[str, Mapping[str, int]]
) -> str | None:
    for name, profile in profiles.items():
        if all(values.get(field) == expected for field, expected in profile.items()):
            return name
    return None


def _ml_kem_named_profile(label: str | None) -> tuple[dict[str, int] | None, str | None, str]:
    if label is None:
        return None, None, "unspecified"
    token = _token(label)
    for name, profile in _ML_KEM_PROFILES.items():
        level = name.rsplit("-", 1)[1]
        if token in {f"mlkem{level}", f"fips203mlkem{level}"}:
            return profile, name, "standard"
        if "kyber" in token and level in token:
            suffix = "-90s" if "90s" in token else ""
            return profile, f"Kyber{level}{suffix}", "legacy"
    return None, label, "unknown"


def _ml_dsa_named_profile(label: str | None) -> tuple[dict[str, int] | None, str | None, str]:
    if label is None:
        return None, None, "unspecified"
    token = _token(label)
    legacy_numbers = {"2": "ML-DSA-44", "3": "ML-DSA-65", "5": "ML-DSA-87"}
    for name, profile in _ML_DSA_PROFILES.items():
        level = name.rsplit("-", 1)[1]
        if token in {f"mldsa{level}", f"fips204mldsa{level}"}:
            return profile, name, "standard"
    if "dilithium" in token:
        for number, standard_name in legacy_numbers.items():
            if token.endswith(number) or f"dilithium{number}" in token:
                return _ML_DSA_PROFILES[standard_name], f"Dilithium{number}", "legacy"
    return None, label, "unknown"


def _normal_hash_family(value: Any) -> str:
    text = _bounded_label(value, "hash_family")
    token = _token(text)
    if token in {"sha2", "sha256", "sha512"}:
        return "sha2"
    if token in {"shake", "shake256"}:
        return "shake"
    if token == "haraka":
        return "haraka"
    raise PQCAuditError("unsupported hash_family label")


def _slh_named_profile(
    label: str | None,
) -> tuple[dict[str, int] | None, str | None, str, str | None]:
    if label is None:
        return None, None, "unspecified", None
    token = _token(label)
    family = None
    if "sha2" in token or "sha256" in token or "sha512" in token:
        family = "sha2"
    elif "shake" in token:
        family = "shake"
    elif "haraka" in token:
        family = "haraka"
    for shape, profile in _SLH_SHAPES.items():
        if shape not in token:
            continue
        if token.startswith("slhdsa") and family in {"sha2", "shake"}:
            return profile, f"SLH-DSA-{family.upper()}-{shape}", "standard", family
        if "sphincs" in token and family is not None:
            flavor = "robust" if "robust" in token else "simple"
            return profile, f"SPHINCS+-{family.upper()}-{shape}-{flavor}", "legacy", family
    return None, label, "unknown", family


def _ml_kem_sizes(values: Mapping[str, int]) -> PQCArtifactSizes:
    n = values["n"]
    k = values["k"]
    coeff_bits = values["coeff_bits"]
    polynomial = _ceil_div(n * coeff_bits, 8)
    pke_key = _checked_size(k * polynomial, "packed PKE key")
    ek = _checked_size(pke_key + values["rho_bytes"], "public key")
    dk = _checked_size(
        pke_key + ek + values["hash_bytes"] + values["z_bytes"], "private key"
    )
    c1 = _checked_size(_ceil_div(k * n * values["du"], 8), "ciphertext c1")
    c2 = _checked_size(_ceil_div(n * values["dv"], 8), "ciphertext c2")
    ciphertext = _checked_size(c1 + c2, "ciphertext")
    return PQCArtifactSizes(
        public_key=ek,
        private_key=dk,
        ciphertext=ciphertext,
        shared_secret=values["shared_secret_bytes"],
        components=(
            ("packed_polynomial", polynomial),
            ("ek_pke", pke_key),
            ("rho", values["rho_bytes"]),
            ("dk_pke", pke_key),
            ("embedded_ek", ek),
            ("embedded_ek_hash", values["hash_bytes"]),
            ("implicit_rejection_z", values["z_bytes"]),
            ("ciphertext_c1", c1),
            ("ciphertext_c2", c2),
        ),
    )


def _ml_dsa_sizes(values: Mapping[str, int]) -> PQCArtifactSizes:
    n = values["n"]
    q_bits = (values["q"] - 1).bit_length()
    t1_bits = q_bits - values["d"]
    if t1_bits <= 0:
        raise PQCAuditError("d leaves no public-key coefficient bits")
    t1_poly = _checked_size(_ceil_div(n * t1_bits, 8), "t1 polynomial")
    secret_bits = (2 * values["eta"]).bit_length()
    secret_poly = _checked_size(_ceil_div(n * secret_bits, 8), "small-secret polynomial")
    t0_poly = _checked_size(_ceil_div(n * values["d"], 8), "t0 polynomial")
    z_bits = 1 + (values["gamma1"] - 1).bit_length()
    z_poly = _checked_size(_ceil_div(n * z_bits, 8), "response polynomial")

    public_key = _checked_size(values["rho_bytes"] + values["k"] * t1_poly, "public key")
    private_key = _checked_size(
        values["rho_bytes"]
        + values["key_bytes"]
        + values["tr_bytes"]
        + (values["l"] + values["k"]) * secret_poly
        + values["k"] * t0_poly,
        "private key",
    )
    hint = _checked_size(
        values["omega"] * values["hint_index_bytes"]
        + values["k"] * values["hint_count_bytes"],
        "hint",
    )
    signature = _checked_size(
        values["challenge_bytes"] + values["l"] * z_poly + hint, "signature"
    )
    return PQCArtifactSizes(
        public_key=public_key,
        private_key=private_key,
        signature=signature,
        components=(
            ("rho", values["rho_bytes"]),
            ("t1_polynomial", t1_poly),
            ("K", values["key_bytes"]),
            ("tr", values["tr_bytes"]),
            ("small_secret_polynomial", secret_poly),
            ("t0_polynomial", t0_poly),
            ("challenge", values["challenge_bytes"]),
            ("response_polynomial", z_poly),
            ("hint", hint),
        ),
    )


def _base_digits(value: int, base: int) -> int:
    digits = 1
    while value >= base:
        value //= base
        digits += 1
    return digits


def _slh_sizes(values: Mapping[str, int]) -> PQCArtifactSizes:
    n = values["n"]
    if values["h"] % values["d"]:
        return PQCArtifactSizes(
            public_key=_checked_size(2 * n, "public key"),
            private_key=_checked_size(4 * n, "private key"),
            components=(("n", n),),
        )
    w = 1 << values["lg_w"]
    wots_len1 = _ceil_div(8 * n, values["lg_w"])
    wots_len2 = _base_digits(wots_len1 * (w - 1), w)
    wots_len = wots_len1 + wots_len2
    h_prime = values["h"] // values["d"]
    randomness = n
    fors = _checked_size(values["k"] * (values["a"] + 1) * n, "FORS signature")
    hypertree = _checked_size(
        (values["h"] + values["d"] * wots_len) * n, "hypertree signature"
    )
    signature = _checked_size(randomness + fors + hypertree, "signature")
    return PQCArtifactSizes(
        public_key=_checked_size(2 * n, "public key"),
        private_key=_checked_size(4 * n, "private key"),
        signature=signature,
        components=(
            ("n", n),
            ("h_prime", h_prime),
            ("wots_len1", wots_len1),
            ("wots_len2", wots_len2),
            ("signature_randomizer", randomness),
            ("fors_signature", fors),
            ("hypertree_signature", hypertree),
        ),
    )


def _audit_ml_kem(source: Mapping[str, Any]) -> PQCAuditResult:
    allowed = _COMMON_LABEL_FIELDS | _ML_KEM_INTEGER_FIELDS | _ML_KEM_BOOLEAN_FIELDS
    _reject_unknown(source, allowed)
    data = dict(source)
    label = _profile_label(data, _ml_kem_named_profile, {"mlkem", "fips203"})
    named_profile, named_variant, label_kind = _ml_kem_named_profile(label)
    _fill_missing(data, named_profile)
    required = ("n", "q", "k", "eta1", "eta2", "du", "dv")
    if any(field not in data for field in required):
        raise PQCAuditError("incomplete ML-KEM parameter profile")
    values = {
        field: _exact_int(
            data[field],
            field,
            maximum=MAX_DIMENSION if field == "n" else (
                MAX_SMALL_PARAMETER if field in {"k", "eta1", "eta2", "du", "dv"} else MAX_INTEGER
            ),
        )
        for field in required
    }
    values["coeff_bits"] = _exact_int(
        data.get("coeff_bits", (values["q"] - 1).bit_length()),
        "coeff_bits",
        maximum=63,
    )
    for field, default in (
        ("rho_bytes", 32),
        ("hash_bytes", 32),
        ("z_bytes", 32),
        ("shared_secret_bytes", 32),
    ):
        values[field] = _exact_int(
            data.get(field, default), field, maximum=MAX_ENCODING_BYTES
        )
        data.setdefault(field, values[field])
    data.setdefault("coeff_bits", values["coeff_bits"])
    for field in required:
        data[field] = values[field]

    findings: list[PQCAuditFinding] = []
    malformed = False
    if not _power_of_two(values["n"]):
        malformed = True
        _finding(findings, "ring_degree_not_power_of_two", "high", "ML-KEM ring degree n must be a power of two")
    if not _is_prime_64(values["q"]):
        malformed = True
        _finding(findings, "nonprime_modulus", "high", "the supplied modulus q is not prime")
    if (values["q"] - 1) % values["n"]:
        malformed = True
        _finding(findings, "missing_ntt_root", "high", "q-1 is not divisible by n for the ML-KEM NTT structure")
    if values["eta1"] >= values["q"] or values["eta2"] >= values["q"]:
        malformed = True
        _finding(findings, "noise_outside_modulus", "high", "a noise bound is not smaller than q")
    if values["du"] > values["coeff_bits"] or values["dv"] > values["coeff_bits"]:
        malformed = True
        _finding(findings, "invalid_compression_width", "high", "a compression width exceeds the coefficient encoding width")
    if values["coeff_bits"] < (values["q"] - 1).bit_length():
        malformed = True
        _finding(findings, "coefficient_width_too_small", "high", "coeff_bits cannot encode all residues modulo q")

    sizes = _ml_kem_sizes(values)
    core = {field: values[field] for field in required}
    exact = _matching_profile(core, _ML_KEM_PROFILES)
    standard_encoding = all(
        values[field] == expected
        for field, expected in {
            "coeff_bits": 12,
            "rho_bytes": 32,
            "hash_bytes": 32,
            "z_bytes": 32,
            "shared_secret_bytes": 32,
        }.items()
    )
    if label_kind == "legacy" and exact is not None and standard_encoding and not malformed:
        classification = "legacy"
        variant = named_variant
        _finding(findings, "legacy_variant", "medium", "Kyber and finalized ML-KEM are not byte-compatible despite matching dimensions")
    elif exact is not None and standard_encoding and label_kind != "legacy" and not malformed:
        classification = "standard"
        variant = exact
    else:
        toy = (
            values["n"] < 256
            or values["n"] * values["k"] < 512
            or values["q"].bit_length() < 12
            or values["k"] < 2
        )
        classification = "malformed" if malformed else ("toy" if toy else "nonstandard")
        variant = named_variant if label is not None else None
        code = "malformed_profile" if malformed else ("toy_profile" if toy else "nonstandard_profile")
        severity = "high" if malformed or toy else "medium"
        _finding(findings, code, severity, f"profile is {classification}, not an approved FIPS 203 parameter set")
        if named_profile is not None and exact is None:
            _finding(findings, "variant_parameter_mismatch", "high", "declared variant does not match its published parameter tuple")

    if values["n"] * values["k"] < 512:
        _finding(findings, "small_module_dimension", "high", "module dimension n*k is below ML-KEM-512")
    if values["eta1"] <= 1 or values["eta2"] <= 1:
        _finding(findings, "thin_noise", "high", "noise bound at or below one is a strong toy-attack indicator")
    if values["dv"] < 4:
        _finding(findings, "aggressive_ciphertext_compression", "medium", "very small dv can create an abnormal decryption-failure surface")

    if _optional_bool(data, "reuse", "randomness_reused", "coins_reused") is True:
        _finding(findings, "randomness_reuse", "critical", "key-generation or encapsulation randomness is reported reused")
    for field, code, severity, detail in (
        ("implicit_rejection", "implicit_rejection_missing", "critical", "decapsulation is reported without implicit rejection"),
        ("modulus_check", "encapsulation_key_check_missing", "high", "the canonical encapsulation-key modulus check is reported absent"),
        ("key_hash_check", "decapsulation_key_hash_check_missing", "high", "the embedded encapsulation-key hash check is reported absent"),
        ("domain_separation", "domain_separation_missing", "high", "finalized key-generation domain separation is reported absent"),
        ("constant_time", "variable_time_path", "high", "secret-dependent processing is reported non-constant-time"),
    ):
        if _optional_bool(data, field) is False:
            _finding(findings, code, severity, detail)
    if _optional_bool(data, "oracle_exposed") is True:
        _finding(findings, "decapsulation_oracle", "critical", "a decapsulation validity or failure oracle is reported exposed")

    return PQCAuditResult(
        "ML-KEM",
        classification,
        variant,
        _freeze_parameters(data, _ML_KEM_INTEGER_FIELDS | _ML_KEM_BOOLEAN_FIELDS),
        sizes,
        tuple(findings),
    )


def _audit_ml_dsa(source: Mapping[str, Any]) -> PQCAuditResult:
    allowed = _COMMON_LABEL_FIELDS | _ML_DSA_INTEGER_FIELDS | _ML_DSA_BOOLEAN_FIELDS
    _reject_unknown(source, allowed)
    data = dict(source)
    label = _profile_label(data, _ml_dsa_named_profile, {"mldsa", "fips204"})
    named_profile, named_variant, label_kind = _ml_dsa_named_profile(label)
    _fill_missing(data, named_profile)
    required = (
        "n", "q", "d", "k", "l", "eta", "tau", "beta", "gamma1",
        "gamma2", "omega", "lambda",
    )
    if any(field not in data for field in required):
        raise PQCAuditError("incomplete ML-DSA parameter profile")
    values: dict[str, int] = {}
    for field in required:
        if field == "q":
            maximum = MAX_INTEGER
        elif field == "n":
            maximum = MAX_DIMENSION
        else:
            maximum = MAX_INTEGER if field in {"gamma1", "gamma2"} else MAX_SMALL_PARAMETER
        values[field] = _exact_int(data[field], field, maximum=maximum)
        data[field] = values[field]

    legacy_encoding = label_kind == "legacy"
    encoding_defaults = {
        "rho_bytes": 32,
        "key_bytes": 32,
        "tr_bytes": 32 if legacy_encoding else 64,
        "challenge_bytes": 32 if legacy_encoding else values["lambda"] // 4,
        "hint_index_bytes": max(1, _ceil_div((values["n"] - 1).bit_length(), 8)),
        "hint_count_bytes": max(1, _ceil_div(values["omega"].bit_length(), 8)),
    }
    for field, default in encoding_defaults.items():
        values[field] = _exact_int(data.get(field, default), field, maximum=MAX_ENCODING_BYTES)
        data.setdefault(field, values[field])

    findings: list[PQCAuditFinding] = []
    malformed = False
    if not _power_of_two(values["n"]):
        malformed = True
        _finding(findings, "ring_degree_not_power_of_two", "high", "ML-DSA ring degree n must be a power of two")
    if not _is_prime_64(values["q"]):
        malformed = True
        _finding(findings, "nonprime_modulus", "high", "the supplied modulus q is not prime")
    if (values["q"] - 1) % (2 * values["n"]):
        malformed = True
        _finding(findings, "missing_ntt_root", "high", "q-1 is not divisible by 2n for the ML-DSA NTT structure")
    if values["d"] >= (values["q"] - 1).bit_length():
        malformed = True
        _finding(findings, "invalid_rounding_width", "high", "d consumes every public-key coefficient bit")
    if values["tau"] > values["n"]:
        malformed = True
        _finding(findings, "challenge_weight_exceeds_ring", "high", "tau exceeds the number of ring coefficients")
    if values["eta"] >= values["q"]:
        malformed = True
        _finding(findings, "secret_bound_outside_modulus", "high", "eta is not smaller than q")
    if not _power_of_two(values["gamma1"]):
        malformed = True
        _finding(findings, "gamma1_not_power_of_two", "high", "gamma1 must be a power of two for the finalized encoding")
    if values["gamma1"] <= values["beta"] or values["gamma2"] <= values["beta"]:
        malformed = True
        _finding(findings, "invalid_rejection_bounds", "high", "gamma1 and gamma2 must exceed beta")
    if values["omega"] > values["k"] * values["n"]:
        malformed = True
        _finding(findings, "hint_weight_exceeds_vector", "high", "omega exceeds the coefficient count in the hint vector")
    if values["lambda"] % 4:
        malformed = True
        _finding(findings, "invalid_challenge_length", "high", "lambda must be divisible by four for the raw challenge encoding")
    if values["hint_index_bytes"] * 8 < (values["n"] - 1).bit_length():
        malformed = True
        _finding(findings, "hint_index_too_narrow", "high", "hint_index_bytes cannot encode every coefficient index")
    if values["hint_count_bytes"] * 8 < values["omega"].bit_length():
        malformed = True
        _finding(findings, "hint_count_too_narrow", "high", "hint_count_bytes cannot encode omega")

    sizes = _ml_dsa_sizes(values)
    core = {field: values[field] for field in required}
    exact = _matching_profile(core, _ML_DSA_PROFILES)
    standard_encoding = all(
        values[field] == expected
        for field, expected in {
            "rho_bytes": 32,
            "key_bytes": 32,
            "tr_bytes": 64,
            "challenge_bytes": values["lambda"] // 4,
            "hint_index_bytes": 1,
            "hint_count_bytes": 1,
        }.items()
    )
    legacy_encoding_match = all(
        values[field] == expected
        for field, expected in {
            "rho_bytes": 32,
            "key_bytes": 32,
            "tr_bytes": 32,
            "challenge_bytes": 32,
            "hint_index_bytes": 1,
            "hint_count_bytes": 1,
        }.items()
    )
    if label_kind == "legacy" and exact is not None and legacy_encoding_match and not malformed:
        classification = "legacy"
        variant = named_variant
        _finding(findings, "legacy_variant", "medium", "Dilithium and finalized ML-DSA use incompatible domain separation and raw encodings")
    elif exact is not None and standard_encoding and label_kind != "legacy" and not malformed:
        classification = "standard"
        variant = exact
    else:
        toy = (
            values["n"] < 256
            or values["n"] * min(values["k"], values["l"]) < 1024
            or values["q"].bit_length() < 23
            or values["lambda"] < 128
            or values["tau"] < 32
        )
        classification = "malformed" if malformed else ("toy" if toy else "nonstandard")
        variant = named_variant if label is not None else None
        code = "malformed_profile" if malformed else ("toy_profile" if toy else "nonstandard_profile")
        severity = "high" if malformed or toy else "medium"
        _finding(findings, code, severity, f"profile is {classification}, not an approved FIPS 204 parameter set")
        if named_profile is not None and exact is None:
            _finding(findings, "variant_parameter_mismatch", "high", "declared variant does not match its published parameter tuple")

    if values["beta"] != values["tau"] * values["eta"]:
        _finding(findings, "unexpected_beta", "medium", "beta differs from tau*eta used by the finalized profiles")
    if values["n"] * min(values["k"], values["l"]) < 1024:
        _finding(findings, "small_module_dimension", "high", "module dimension is below ML-DSA-44")
    if values["lambda"] < 128:
        _finding(findings, "short_challenge_hash", "high", "challenge hash parameter lambda is below 128")
    if values["tau"] < 32:
        _finding(findings, "low_challenge_weight", "high", "low challenge weight is a toy-parameter attack indicator")

    if _optional_bool(data, "reuse", "randomness_reused", "nonce_reuse") is True:
        _finding(findings, "signing_nonce_reuse", "critical", "the ephemeral signing mask/randomness is reported reused")
    for field, code, severity, detail in (
        ("norm_checks", "norm_checks_missing", "critical", "signature rejection/norm checks are reported absent"),
        ("hint_checks", "hint_checks_missing", "critical", "canonical hint and hint-weight checks are reported absent"),
        ("domain_separation", "domain_separation_missing", "high", "finalized message/key domain separation is reported absent"),
        ("constant_time", "variable_time_path", "high", "secret-dependent signing is reported non-constant-time"),
    ):
        if _optional_bool(data, field) is False:
            _finding(findings, code, severity, detail)
    if _optional_bool(data, "side_channel_exposed") is True:
        _finding(findings, "side_channel_exposure", "critical", "a signing side channel is explicitly reported exposed")
    if _optional_bool(data, "hedged_signing") is False:
        _finding(findings, "deterministic_signing", "info", "deterministic signing is allowed, but removes the hedge against some fault/side-channel attacks")

    return PQCAuditResult(
        "ML-DSA",
        classification,
        variant,
        _freeze_parameters(data, _ML_DSA_INTEGER_FIELDS | _ML_DSA_BOOLEAN_FIELDS),
        sizes,
        tuple(findings),
    )


def _audit_slh_dsa(source: Mapping[str, Any]) -> PQCAuditResult:
    allowed = _COMMON_LABEL_FIELDS | _SLH_INTEGER_FIELDS | _SLH_STRING_FIELDS | _SLH_BOOLEAN_FIELDS
    _reject_unknown(source, allowed)
    data = dict(source)
    label = _profile_label(data, _slh_named_profile, {"slhdsa", "fips205"})
    named_profile, named_variant, label_kind, named_family = _slh_named_profile(label)
    _fill_missing(data, named_profile)
    if "hash_family" not in data and named_family is not None:
        data["hash_family"] = named_family
    if "lg_w" not in data and "w" in data:
        w_value = _exact_int(data["w"], "w", maximum=1 << 16)
        if not _power_of_two(w_value):
            raise PQCAuditError("w must be a power of two")
        data["lg_w"] = w_value.bit_length() - 1
    required = ("n", "h", "d", "a", "k", "lg_w")
    if any(field not in data for field in required) or "hash_family" not in data:
        raise PQCAuditError("incomplete SLH-DSA parameter profile")
    values: dict[str, int] = {}
    for field in required:
        maximum = MAX_DIMENSION if field in {"n", "h"} else MAX_SMALL_PARAMETER
        values[field] = _exact_int(data[field], field, maximum=maximum)
        data[field] = values[field]
    if "w" in data:
        supplied_w = _exact_int(data["w"], "w", maximum=1 << 16)
        if supplied_w != 1 << values["lg_w"]:
            raise PQCAuditError("w and lg_w disagree")
        data["w"] = supplied_w
    family = _normal_hash_family(data["hash_family"])
    data["hash_family"] = family

    findings: list[PQCAuditFinding] = []
    malformed = False
    if values["h"] % values["d"]:
        malformed = True
        _finding(findings, "uneven_hypertree", "high", "h must be divisible by d")
    if values["d"] > values["h"]:
        malformed = True
        _finding(findings, "too_many_hypertree_layers", "high", "d exceeds the total tree height h")
    if not 1 <= values["lg_w"] <= 16:
        malformed = True
        _finding(findings, "invalid_winternitz_width", "high", "lg_w is outside the bounded Winternitz range")
    if values["k"] * values["a"] > MAX_INTEGER:
        malformed = True
        _finding(findings, "fors_parameter_overflow", "high", "FORS parameter product exceeds the supported range")
    if values["h"] % values["d"] == 0 and values["h"] // values["d"] > 32:
        _finding(findings, "large_subtree_height", "medium", "unusually large XMSS subtrees make this profile impractical")

    sizes = _slh_sizes(values)
    shape_match = None
    for shape, profile in _SLH_SHAPES.items():
        if all(values[field] == expected for field, expected in profile.items()):
            shape_match = shape
            break
    standard_name = (
        f"SLH-DSA-{family.upper()}-{shape_match}"
        if family in {"sha2", "shake"} and shape_match is not None
        else None
    )
    if label_kind == "legacy" and shape_match is not None and not malformed:
        classification = "legacy"
        variant = named_variant
        _finding(findings, "legacy_variant", "medium", "SPHINCS+ and finalized SLH-DSA are not byte-compatible despite matching lengths")
    elif standard_name is not None and label_kind != "legacy" and not malformed:
        classification = "standard"
        variant = standard_name
    else:
        toy = values["n"] < 16 or values["h"] < 48 or values["k"] * values["a"] < 128
        classification = "malformed" if malformed else ("toy" if toy else "nonstandard")
        variant = named_variant if label is not None else None
        code = "malformed_profile" if malformed else ("toy_profile" if toy else "nonstandard_profile")
        severity = "high" if malformed or toy else "medium"
        _finding(findings, code, severity, f"profile is {classification}, not an approved FIPS 205 parameter set")
        if named_profile is not None and shape_match is None:
            _finding(findings, "variant_parameter_mismatch", "high", "declared variant does not match its published parameter tuple")

    if values["n"] < 16:
        _finding(findings, "short_hash_output", "critical", "n below 16 bytes makes generic hash attacks CTF-feasible")
    if values["h"] < 48:
        _finding(findings, "short_hypertree", "high", "the hypertree height is far below finalized profiles")
    if values["k"] * values["a"] < 128:
        _finding(findings, "small_fors_message_space", "high", "FORS signs fewer than 128 digest bits")
    if values["lg_w"] > 8:
        _finding(findings, "large_winternitz_base", "medium", "large Winternitz bases create unusual time/size tradeoffs")

    if _optional_bool(data, "reuse", "randomness_reused") is True:
        _finding(findings, "randomizer_reuse", "medium", "signature randomizer reuse is reported; inspect deterministic/hedged mode and traces")
    address_check = _optional_bool(data, "address_checks", "address_domain_separation")
    if address_check is False:
        _finding(findings, "address_separation_missing", "critical", "ADRS type/field domain separation is reported absent")
    for field, code, severity, detail in (
        ("domain_separation", "domain_separation_missing", "critical", "hash-call domain separation is reported absent"),
        ("root_check", "root_check_missing", "critical", "verification is reported not to compare the reconstructed hypertree root"),
        ("context_binding", "context_binding_missing", "high", "pure/pre-hash context binding is reported absent"),
        ("constant_time", "variable_time_path", "medium", "secret-dependent signing is reported non-constant-time"),
        ("fault_checks", "fault_checks_missing", "medium", "fault-detection checks are reported absent"),
    ):
        if _optional_bool(data, field) is False:
            _finding(findings, code, severity, detail)

    return PQCAuditResult(
        "SLH-DSA",
        classification,
        variant,
        _freeze_parameters(
            data, _SLH_INTEGER_FIELDS | _SLH_STRING_FIELDS | _SLH_BOOLEAN_FIELDS
        ),
        sizes,
        tuple(findings),
    )


def audit_ml_kem(*args: Any, **kwargs: Any) -> PQCAuditResult | None:
    """Audit one ML-KEM/Kyber-like profile; return ``None`` on malformed input."""

    try:
        return _audit_ml_kem(_copy_call(args, kwargs))
    except Exception:
        return None


def audit_ml_dsa(*args: Any, **kwargs: Any) -> PQCAuditResult | None:
    """Audit one ML-DSA/Dilithium-like profile; return ``None`` on malformed input."""

    try:
        return _audit_ml_dsa(_copy_call(args, kwargs))
    except Exception:
        return None


def audit_slh_dsa(*args: Any, **kwargs: Any) -> PQCAuditResult | None:
    """Audit one SLH-DSA/SPHINCS+-like profile; return ``None`` on malformed input."""

    try:
        return _audit_slh_dsa(_copy_call(args, kwargs))
    except Exception:
        return None


def audit_parameters(*args: Any, **kwargs: Any) -> PQCAuditResult | None:
    """Dispatch an audit using a bounded ``scheme`` field or positional label.

    Examples are ``audit_parameters({"scheme": "ML-KEM", ...})`` and
    ``audit_parameters("SLH-DSA", n=..., ...)``.  Syntactically malformed or
    incomplete evidence returns ``None``.
    """

    try:
        if args and isinstance(args[0], str):
            if len(args) > 2:
                raise PQCAuditError("too many positional arguments")
            scheme = args[0]
            remainder = args[1:]
            data = _copy_call(remainder, kwargs)
            if "scheme" in data:
                raise PQCAuditError("duplicate scheme")
            data["scheme"] = scheme
        else:
            data = _copy_call(args, kwargs)
        if "scheme" not in data:
            raise PQCAuditError("scheme is required")
        scheme = _bounded_label(data["scheme"], "scheme")
        token = _token(scheme)
        if token in {"mlkem", "fips203", "kyber"}:
            return _audit_ml_kem(data)
        if token in {"mldsa", "fips204", "dilithium"}:
            return _audit_ml_dsa(data)
        if token in {"slhdsa", "fips205", "sphincs", "sphincsplus"}:
            return _audit_slh_dsa(data)
        raise PQCAuditError("unsupported PQC scheme")
    except Exception:
        return None


def _result_json(result: PQCAuditResult) -> dict[str, Any]:
    sizes = result.sizes
    return {
        "scheme": result.scheme,
        "classification": result.classification,
        "variant": result.variant,
        "parameters": dict(result.parameters),
        "sizes": {
            "public_key": sizes.public_key,
            "private_key": sizes.private_key,
            "ciphertext": sizes.ciphertext,
            "signature": sizes.signature,
            "shared_secret": sizes.shared_secret,
            "components": dict(sizes.components),
        },
        "findings": [
            {"code": item.code, "severity": item.severity, "detail": item.detail}
            for item in result.findings
        ],
        "warning": "A standard profile or empty finding list is not a security claim.",
    }


def _load_json_file(path_text: str) -> dict[str, Any]:
    try:
        path = Path(path_text)
        size = path.stat().st_size
        if size > MAX_JSON_BYTES:
            raise PQCAuditError("JSON input exceeds the 1 MiB cap")
        text = path.read_text(encoding="utf-8")
        value = json.loads(text)
    except PQCAuditError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, MemoryError) as exc:
        raise PQCAuditError("unable to read a bounded JSON object") from exc
    if not isinstance(value, dict) or len(value) > MAX_FIELDS:
        raise PQCAuditError("JSON root must be a bounded object")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptodepth_pqc_audit",
        description="Offline FIPS 203/204/205 and toy PQC parameter-profile audit",
    )
    parser.add_argument("json_file", help="bounded JSON object containing scheme and parameters")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Guarded JSON-file CLI; malformed local evidence returns status 2."""

    parser = _build_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        data = _load_json_file(args.json_file)
        result = audit_parameters(data)
        if result is None:
            raise PQCAuditError("malformed, incomplete, or unsupported parameter profile")
        print(
            json.dumps(
                _result_json(result),
                indent=2 if args.pretty else None,
                sort_keys=True,
                separators=None if args.pretty else (",", ":"),
            )
        )
        return 0
    except PQCAuditError as exc:
        print(f"cryptodepth_pqc_audit: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("cryptodepth_pqc_audit: unable to audit input", file=sys.stderr)
        return 2


__all__ = [
    "PQCAuditError",
    "PQCAuditFinding",
    "PQCArtifactSizes",
    "PQCAuditResult",
    "audit_ml_kem",
    "audit_ml_dsa",
    "audit_slh_dsa",
    "audit_parameters",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
