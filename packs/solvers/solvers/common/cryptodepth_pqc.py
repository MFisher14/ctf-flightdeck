#!/usr/bin/env python3
"""Strict offline parsers for finalized NIST post-quantum raw objects.

The module recognizes and structurally parses the raw byte encodings specified by
FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).  It does not perform
encapsulation, decapsulation, signing, verification, networking, or execution.

Raw lengths are not always unique.  In particular, an ML-KEM-1024 encapsulation
key and ciphertext are both 1568 bytes, while SLH-DSA SHA2/SHAKE keys have the
same encodings and sizes.  :func:`identify_pqc` therefore returns every valid
interpretation rather than guessing one.

Public strict parsers raise only :class:`PQCParseError`.  The identifier is the
fail-closed convenience API: malformed or unsupported input returns ``()``.

CLI examples::

    .venv/bin/python solvers/common/cryptodepth_pqc.py blob.bin --json
    .venv/bin/python solvers/common/cryptodepth_pqc.py blob.hex \
        --encoding hex --family ml-kem --kind encapsulation_key --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


MAX_OBJECT_BYTES = 64 * 1024
MAX_HEX_FILE_BYTES = 2 * MAX_OBJECT_BYTES + 4096
MLKEM_Q = 3329


class PQCParseError(ValueError):
    """The supplied bytes are not the requested finalized PQC object."""


@dataclass(frozen=True)
class PQCField:
    """One half-open field interval within a raw object."""

    name: str
    offset: int
    length: int
    description: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass(frozen=True)
class PQCObject:
    """Immutable structural interpretation of one raw PQC object."""

    standard: str
    family: str
    parameter_set: str
    kind: str
    length: int
    fields: tuple[PQCField, ...]
    parameters: tuple[tuple[str, int | str], ...]
    checks: tuple[str, ...]

    def field(self, name: str) -> PQCField | None:
        """Return a uniquely named field, or ``None`` when it is absent."""

        matches = tuple(item for item in self.fields if item.name == name)
        return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class _MLKEMProfile:
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    ek_bytes: int
    dk_bytes: int
    ct_bytes: int


@dataclass(frozen=True)
class _MLDSAProfile:
    name: str
    k: int
    ell: int
    eta: int
    gamma1: int
    omega: int
    lambda_bits: int
    pk_bytes: int
    sk_bytes: int
    sig_bytes: int

    @property
    def secret_poly_bytes(self) -> int:
        return 96 if self.eta == 2 else 128

    @property
    def z_poly_bytes(self) -> int:
        return 576 if self.gamma1 == 1 << 17 else 640


@dataclass(frozen=True)
class _SLHDSAProfile:
    name: str
    hash_family: str
    n: int
    h: int
    d: int
    a: int
    k: int
    lg_w: int = 4

    @property
    def h_prime(self) -> int:
        return self.h // self.d

    @property
    def wots_len(self) -> int:
        # FIPS 205 Section 5.2: len_1=ceil(8n/lg_w),
        # len_2=floor(log_w(len_1*(w-1)))+1.  All approved sets use w=16.
        w = 1 << self.lg_w
        len_1 = (8 * self.n + self.lg_w - 1) // self.lg_w
        maximum = len_1 * (w - 1)
        len_2 = 0
        while maximum:
            len_2 += 1
            maximum //= w
        return len_1 + len_2

    @property
    def pk_bytes(self) -> int:
        return 2 * self.n

    @property
    def sk_bytes(self) -> int:
        return 4 * self.n

    @property
    def fors_bytes(self) -> int:
        return self.k * (self.a + 1) * self.n

    @property
    def ht_bytes(self) -> int:
        return self.d * (self.wots_len + self.h_prime) * self.n

    @property
    def sig_bytes(self) -> int:
        return self.n + self.fors_bytes + self.ht_bytes


_MLKEM_PROFILES = (
    _MLKEMProfile("ML-KEM-512", 2, 3, 2, 10, 4, 800, 1632, 768),
    _MLKEMProfile("ML-KEM-768", 3, 2, 2, 10, 4, 1184, 2400, 1088),
    _MLKEMProfile("ML-KEM-1024", 4, 2, 2, 11, 5, 1568, 3168, 1568),
)

_MLDSA_PROFILES = (
    _MLDSAProfile("ML-DSA-44", 4, 4, 2, 1 << 17, 80, 128, 1312, 2560, 2420),
    _MLDSAProfile("ML-DSA-65", 6, 5, 4, 1 << 19, 55, 192, 1952, 4032, 3309),
    _MLDSAProfile("ML-DSA-87", 8, 7, 2, 1 << 19, 75, 256, 2592, 4896, 4627),
)


def _slh_pair(stem: str, n: int, h: int, d: int, a: int, k: int):
    return (
        _SLHDSAProfile(f"SLH-DSA-SHA2-{stem}", "SHA2", n, h, d, a, k),
        _SLHDSAProfile(f"SLH-DSA-SHAKE-{stem}", "SHAKE", n, h, d, a, k),
    )


_SLHDSA_PROFILES = (
    *_slh_pair("128s", 16, 63, 7, 12, 14),
    *_slh_pair("128f", 16, 66, 22, 6, 33),
    *_slh_pair("192s", 24, 63, 7, 14, 17),
    *_slh_pair("192f", 24, 66, 22, 8, 33),
    *_slh_pair("256s", 32, 64, 8, 14, 22),
    *_slh_pair("256f", 32, 68, 17, 9, 35),
)

_FAMILY_ORDER = ("ML-KEM", "ML-DSA", "SLH-DSA")
_KIND_ORDER = {
    "ML-KEM": ("encapsulation_key", "decapsulation_key", "ciphertext"),
    "ML-DSA": ("public_key", "private_key", "signature"),
    "SLH-DSA": ("public_key", "private_key", "signature"),
}


def _coerce_bytes(value) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, (bytearray, memoryview)):
        result = bytes(value)
    else:
        raise PQCParseError("object must be bytes-like")
    if not result:
        raise PQCParseError("object is empty")
    if len(result) > MAX_OBJECT_BYTES:
        raise PQCParseError(f"object exceeds {MAX_OBJECT_BYTES}-byte cap")
    return result


def _normalise_family(value) -> str:
    token = str(value).strip().upper().replace("_", "-").replace(" ", "-")
    compact = token.replace("-", "")
    aliases = {"MLKEM": "ML-KEM", "MLDSA": "ML-DSA", "SLHDSA": "SLH-DSA"}
    if compact not in aliases:
        raise PQCParseError(f"unsupported PQC family {value!r}")
    return aliases[compact]


def _normalise_parameter(value, family: str) -> str:
    token = str(value).strip().replace("_", "-")
    if family == "ML-KEM" and token.isdecimal():
        token = f"ML-KEM-{token}"
    elif family == "ML-DSA" and token.isdecimal():
        token = f"ML-DSA-{token}"
    elif family == "SLH-DSA" and not token.upper().startswith("SLH-DSA-"):
        token = f"SLH-DSA-{token}"
    return token.upper().replace("SHAKE-", "SHAKE-").replace("SHA2-", "SHA2-")


def _normalise_kind(value, family: str) -> str:
    token = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    common = {
        "pk": "public_key",
        "sk": "private_key",
        "secret_key": "private_key",
        "sig": "signature",
    }
    token = common.get(token, token)
    if family == "ML-KEM":
        token = {
            "ek": "encapsulation_key",
            "pk": "encapsulation_key",
            "public_key": "encapsulation_key",
            "dk": "decapsulation_key",
            "sk": "decapsulation_key",
            "private_key": "decapsulation_key",
            "secret_key": "decapsulation_key",
            "ct": "ciphertext",
        }.get(token, token)
    if token not in _KIND_ORDER[family]:
        raise PQCParseError(f"unsupported {family} object kind {value!r}")
    return token


def _profile(profiles, name: str, family: str):
    for candidate in profiles:
        if candidate.name.upper() == name.upper():
            return candidate
    raise PQCParseError(f"unsupported {family} parameter set {name!r}")


def _fields_cover(fields: tuple[PQCField, ...], total: int) -> None:
    cursor = 0
    for item in fields:
        if item.offset != cursor or item.length < 0:
            raise PQCParseError("internal field layout is not contiguous")
        cursor = item.end
    if cursor != total:
        raise PQCParseError("field layout does not cover the object")


def _validate_mlkem_polynomials(encoded: bytes, label: str) -> None:
    if len(encoded) % 384:
        raise PQCParseError(f"{label} is not a sequence of packed ML-KEM polynomials")
    coefficient = 0
    for offset in range(0, len(encoded), 3):
        first = encoded[offset] | ((encoded[offset + 1] & 0x0F) << 8)
        second = (encoded[offset + 1] >> 4) | (encoded[offset + 2] << 4)
        if first >= MLKEM_Q:
            raise PQCParseError(
                f"{label} coefficient {coefficient} is noncanonical ({first} >= {MLKEM_Q})"
            )
        if second >= MLKEM_Q:
            raise PQCParseError(
                f"{label} coefficient {coefficient + 1} is noncanonical ({second} >= {MLKEM_Q})"
            )
        coefficient += 2


def _mlkem_parameters(profile: _MLKEMProfile):
    return (
        ("n", 256), ("q", MLKEM_Q), ("k", profile.k),
        ("eta1", profile.eta1), ("eta2", profile.eta2),
        ("du", profile.du), ("dv", profile.dv),
    )


def _parse_mlkem(data: bytes, profile: _MLKEMProfile, kind: str) -> PQCObject:
    expected = {
        "encapsulation_key": profile.ek_bytes,
        "decapsulation_key": profile.dk_bytes,
        "ciphertext": profile.ct_bytes,
    }[kind]
    if len(data) != expected:
        raise PQCParseError(f"{profile.name} {kind} must be {expected} bytes, got {len(data)}")
    fields: list[PQCField] = []
    checks = ["exact_length"]
    if kind == "encapsulation_key":
        packed = 384 * profile.k
        for index in range(profile.k):
            fields.append(PQCField(f"t_hat[{index}]", 384 * index, 384, "12-bit NTT coefficients"))
        fields.append(PQCField("rho", packed, 32, "matrix seed"))
        _validate_mlkem_polynomials(data[:packed], "encapsulation key")
        checks.append("fips_203_modulus_canonicality")
    elif kind == "decapsulation_key":
        pke = 384 * profile.k
        embedded_start = pke
        hash_start = embedded_start + profile.ek_bytes
        fields.extend((
            PQCField("dk_pke", 0, pke, "K-PKE decryption key"),
            PQCField("embedded_ek", embedded_start, profile.ek_bytes, "embedded encapsulation key"),
            PQCField("embedded_h_ek", hash_start, 32, "SHA3-256 of embedded_ek"),
            PQCField("z", hash_start + 32, 32, "implicit-rejection secret"),
        ))
        embedded = data[embedded_start:hash_start]
        _validate_mlkem_polynomials(embedded[:pke], "embedded encapsulation key")
        if hashlib.sha3_256(embedded).digest() != data[hash_start:hash_start + 32]:
            raise PQCParseError("decapsulation-key hash does not match embedded encapsulation key")
        checks.extend(("embedded_ek_modulus_canonicality", "embedded_ek_sha3_256"))
    else:
        c1_bytes = 32 * profile.du * profile.k
        c2_bytes = 32 * profile.dv
        fields.extend((
            PQCField("c1", 0, c1_bytes, f"compressed vector u ({profile.du} bits/coefficient)"),
            PQCField("c2", c1_bytes, c2_bytes, f"compressed polynomial v ({profile.dv} bits/coefficient)"),
        ))
        checks.append("compressed_fields_full_bit_range")
    result = PQCObject("FIPS 203", "ML-KEM", profile.name, kind, len(data),
                       tuple(fields), _mlkem_parameters(profile), tuple(checks))
    _fields_cover(result.fields, len(data))
    return result


def parse_mlkem(data, parameter_set, kind) -> PQCObject:
    """Strictly parse one requested FIPS 203 raw object.

    Only :class:`PQCParseError` escapes for malformed arguments or bytes.
    """

    try:
        raw = _coerce_bytes(data)
        name = _normalise_parameter(parameter_set, "ML-KEM")
        profile = _profile(_MLKEM_PROFILES, name, "ML-KEM")
        return _parse_mlkem(raw, profile, _normalise_kind(kind, "ML-KEM"))
    except PQCParseError:
        raise
    except Exception as exc:  # fail closed at the public boundary
        raise PQCParseError("malformed ML-KEM object") from exc


def _unpack_little_symbols(encoded: bytes, width: int, count: int):
    accumulator = int.from_bytes(encoded, "little")
    mask = (1 << width) - 1
    for index in range(count):
        yield (accumulator >> (index * width)) & mask


def _validate_mldsa_secret_poly(encoded: bytes, eta: int, label: str) -> None:
    width = 3 if eta == 2 else 4
    expected = 32 * width
    if len(encoded) != expected:
        raise PQCParseError(f"{label} must be {expected} bytes")
    for index, symbol in enumerate(_unpack_little_symbols(encoded, width, 256)):
        if symbol > 2 * eta:
            raise PQCParseError(
                f"{label} symbol {index} is outside 0..{2 * eta} ({symbol})"
            )


def _validate_mldsa_hint(data: bytes, omega: int, k: int) -> None:
    indices, endpoints = data[:omega], data[omega:]
    if len(endpoints) != k:
        raise PQCParseError("ML-DSA hint endpoint count is malformed")
    cursor = 0
    for polynomial, endpoint in enumerate(endpoints):
        if endpoint < cursor or endpoint > omega:
            raise PQCParseError(f"hint endpoint {polynomial} is decreasing or exceeds omega")
        previous = -1
        for position in range(cursor, endpoint):
            value = indices[position]
            if value <= previous:
                raise PQCParseError(f"hint indices for polynomial {polynomial} are not increasing")
            previous = value
        cursor = endpoint
    if any(indices[cursor:]):
        raise PQCParseError("unused ML-DSA hint-index padding is nonzero")


def _mldsa_parameters(profile: _MLDSAProfile):
    return (
        ("n", 256), ("q", 8380417), ("k", profile.k), ("l", profile.ell),
        ("eta", profile.eta), ("gamma1", profile.gamma1),
        ("omega", profile.omega), ("lambda", profile.lambda_bits),
    )


def _parse_mldsa(data: bytes, profile: _MLDSAProfile, kind: str) -> PQCObject:
    expected = {"public_key": profile.pk_bytes, "private_key": profile.sk_bytes,
                "signature": profile.sig_bytes}[kind]
    if len(data) != expected:
        raise PQCParseError(f"{profile.name} {kind} must be {expected} bytes, got {len(data)}")
    fields: list[PQCField] = []
    checks = ["exact_length"]
    if kind == "public_key":
        fields.append(PQCField("rho", 0, 32, "matrix seed"))
        cursor = 32
        for index in range(profile.k):
            fields.append(PQCField(f"t1[{index}]", cursor, 320, "10-bit packed polynomial"))
            cursor += 320
        checks.append("t1_full_bit_range")
    elif kind == "private_key":
        fields.extend((
            PQCField("rho", 0, 32, "matrix seed"),
            PQCField("K", 32, 32, "signing seed"),
            PQCField("tr", 64, 64, "public-key hash"),
        ))
        cursor = 128
        for group, count in (("s1", profile.ell), ("s2", profile.k)):
            for index in range(count):
                length = profile.secret_poly_bytes
                field = PQCField(f"{group}[{index}]", cursor, length,
                                 f"eta={profile.eta} packed polynomial")
                fields.append(field)
                _validate_mldsa_secret_poly(data[field.offset:field.end], profile.eta, field.name)
                cursor = field.end
        for index in range(profile.k):
            fields.append(PQCField(f"t0[{index}]", cursor, 416, "13-bit packed polynomial"))
            cursor += 416
        checks.extend(("s1_symbols_in_range", "s2_symbols_in_range", "t0_full_bit_range"))
    else:
        challenge_bytes = profile.lambda_bits // 4
        fields.append(PQCField("c_tilde", 0, challenge_bytes, "signature challenge hash"))
        cursor = challenge_bytes
        for index in range(profile.ell):
            fields.append(PQCField(f"z[{index}]", cursor, profile.z_poly_bytes,
                                   "packed response polynomial"))
            cursor += profile.z_poly_bytes
        fields.extend((
            PQCField("hint_indices", cursor, profile.omega, "nonzero hint coefficient indices"),
            PQCField("hint_endpoints", cursor + profile.omega, profile.k,
                     "cumulative per-polynomial endpoints"),
        ))
        _validate_mldsa_hint(data[cursor:], profile.omega, profile.k)
        checks.extend(("z_full_bit_range", "canonical_hint_encoding"))
    result = PQCObject("FIPS 204", "ML-DSA", profile.name, kind, len(data),
                       tuple(fields), _mldsa_parameters(profile), tuple(checks))
    _fields_cover(result.fields, len(data))
    return result


def parse_mldsa(data, parameter_set, kind) -> PQCObject:
    """Strictly parse one requested FIPS 204 raw object."""

    try:
        raw = _coerce_bytes(data)
        name = _normalise_parameter(parameter_set, "ML-DSA")
        profile = _profile(_MLDSA_PROFILES, name, "ML-DSA")
        return _parse_mldsa(raw, profile, _normalise_kind(kind, "ML-DSA"))
    except PQCParseError:
        raise
    except Exception as exc:
        raise PQCParseError("malformed ML-DSA object") from exc


def _slhdsa_parameters(profile: _SLHDSAProfile):
    return (
        ("hash_family", profile.hash_family), ("n", profile.n), ("h", profile.h),
        ("d", profile.d), ("h_prime", profile.h_prime), ("a", profile.a),
        ("k", profile.k), ("lg_w", profile.lg_w), ("wots_len", profile.wots_len),
    )


def _parse_slhdsa(data: bytes, profile: _SLHDSAProfile, kind: str) -> PQCObject:
    expected = {"public_key": profile.pk_bytes, "private_key": profile.sk_bytes,
                "signature": profile.sig_bytes}[kind]
    if len(data) != expected:
        raise PQCParseError(f"{profile.name} {kind} must be {expected} bytes, got {len(data)}")
    n = profile.n
    if profile.h % profile.d:
        raise PQCParseError("SLH-DSA hypertree height is not divisible by layer count")
    if kind == "public_key":
        fields = (
            PQCField("pk_seed", 0, n, "public hash seed"),
            PQCField("pk_root", n, n, "hypertree root"),
        )
    elif kind == "private_key":
        fields = (
            PQCField("sk_seed", 0, n, "secret seed"),
            PQCField("sk_prf", n, n, "message-randomization PRF seed"),
            PQCField("pk_seed", 2 * n, n, "public hash seed"),
            PQCField("pk_root", 3 * n, n, "hypertree root"),
        )
    else:
        fields = (
            PQCField("R", 0, n, "message-dependent randomizer"),
            PQCField("FORS", n, profile.fors_bytes, "FORS signature"),
            PQCField("HT", n + profile.fors_bytes, profile.ht_bytes,
                     "hypertree of WOTS+ and authentication paths"),
        )
    result = PQCObject(
        "FIPS 205", "SLH-DSA", profile.name, kind, len(data), fields,
        _slhdsa_parameters(profile),
        ("exact_length", "fixed_width_byte_fields", "derived_fors_and_hypertree_sizes"),
    )
    _fields_cover(result.fields, len(data))
    return result


def parse_slhdsa(data, parameter_set, kind) -> PQCObject:
    """Strictly parse one requested FIPS 205 raw object."""

    try:
        raw = _coerce_bytes(data)
        name = _normalise_parameter(parameter_set, "SLH-DSA")
        profile = _profile(_SLHDSA_PROFILES, name, "SLH-DSA")
        return _parse_slhdsa(raw, profile, _normalise_kind(kind, "SLH-DSA"))
    except PQCParseError:
        raise
    except Exception as exc:
        raise PQCParseError("malformed SLH-DSA object") from exc


def parse_pqc(data, family, parameter_set, kind) -> PQCObject:
    """Dispatch a strict raw parser by family, raising only ``PQCParseError``."""

    try:
        canonical = _normalise_family(family)
        if canonical == "ML-KEM":
            return parse_mlkem(data, parameter_set, kind)
        if canonical == "ML-DSA":
            return parse_mldsa(data, parameter_set, kind)
        return parse_slhdsa(data, parameter_set, kind)
    except PQCParseError:
        raise
    except Exception as exc:
        raise PQCParseError("malformed PQC object") from exc


def _filter_tokens(values, normaliser, *, none_means_all=True):
    if values is None and none_means_all:
        return None
    if isinstance(values, str):
        values = (values,)
    return frozenset(normaliser(item) for item in values)


def identify_pqc(
    data,
    *,
    families: Iterable[str] | str | None = None,
    kinds: Iterable[str] | str | None = None,
    parameter_sets: Iterable[str] | str | None = None,
) -> tuple[PQCObject, ...]:
    """Return every structurally valid finalized-PQC interpretation.

    The result is deliberately a tuple: multiple entries are evidence of an
    encoding ambiguity, not a ranking.  Malformed arguments or bytes return
    ``()`` and never leak a stdlib exception.
    """

    try:
        raw = _coerce_bytes(data)
        family_filter = _filter_tokens(families, _normalise_family)
        if isinstance(parameter_sets, str):
            parameter_sets = (parameter_sets,)
        raw_parameter_filter = None if parameter_sets is None else tuple(parameter_sets)
        if isinstance(kinds, str):
            kinds = (kinds,)
        raw_kind_filter = None if kinds is None else tuple(kinds)
        matches: list[PQCObject] = []
        family_profiles = (
            ("ML-KEM", _MLKEM_PROFILES, _parse_mlkem),
            ("ML-DSA", _MLDSA_PROFILES, _parse_mldsa),
            ("SLH-DSA", _SLHDSA_PROFILES, _parse_slhdsa),
        )
        for family, profiles, parser in family_profiles:
            if family_filter is not None and family not in family_filter:
                continue
            parameter_filter = None
            if raw_parameter_filter is not None:
                parameter_filter = {
                    _normalise_parameter(item, family) for item in raw_parameter_filter
                }
            kind_filter = None
            if raw_kind_filter is not None:
                # A cross-family query such as ``encapsulation_key`` is valid for
                # ML-KEM and simply inapplicable to the signature families.  Do
                # not let that expected mismatch discard matches from another
                # family.  Truly malformed filters still fail closed to no match.
                kind_filter = set()
                for item in raw_kind_filter:
                    try:
                        kind_filter.add(_normalise_kind(item, family))
                    except PQCParseError:
                        continue
                if not kind_filter:
                    continue
            for profile in profiles:
                if parameter_filter is not None and profile.name.upper() not in parameter_filter:
                    continue
                for kind in _KIND_ORDER[family]:
                    if kind_filter is not None and kind not in kind_filter:
                        continue
                    try:
                        matches.append(parser(raw, profile, kind))
                    except PQCParseError:
                        continue
        return tuple(matches)
    except Exception:
        return ()


def pqc_object_to_dict(value: PQCObject) -> dict:
    """Convert a parser result to a stable JSON-friendly dictionary."""

    try:
        if not isinstance(value, PQCObject):
            raise PQCParseError("value is not a PQCObject")
        result = asdict(value)
        for field, encoded in zip(value.fields, result["fields"]):
            encoded["end"] = field.end
        result["parameters"] = {key: item for key, item in value.parameters}
        return result
    except PQCParseError:
        raise
    except Exception as exc:
        raise PQCParseError("could not serialize PQC parse result") from exc


def _read_cli_input(path_value: str, encoding: str) -> bytes:
    try:
        path = Path(path_value)
        limit = MAX_OBJECT_BYTES if encoding == "raw" else MAX_HEX_FILE_BYTES
        if not path.is_file() or path.stat().st_size > limit:
            raise PQCParseError(f"input file is absent or exceeds the {limit}-byte cap")
        supplied = path.read_bytes()
        if encoding == "raw":
            return _coerce_bytes(supplied)
        try:
            text = supplied.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise PQCParseError("hex input is not ASCII") from exc
        if text.lower().startswith("0x"):
            text = text[2:]
        try:
            decoded = bytes.fromhex(text)
        except ValueError as exc:
            raise PQCParseError("hex input is malformed") from exc
        return _coerce_bytes(decoded)
    except PQCParseError:
        raise
    except (OSError, OverflowError, ValueError) as exc:
        raise PQCParseError("could not read bounded input file") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptodepth_pqc.py",
        description="Identify strict raw FIPS 203/204/205 objects without guessing ambiguities.",
    )
    parser.add_argument("input", help="bounded raw or ASCII-hex file")
    parser.add_argument("--encoding", choices=("raw", "hex"), default="raw")
    parser.add_argument("--family", action="append", choices=("ml-kem", "ml-dsa", "slh-dsa"))
    parser.add_argument("--kind", action="append", choices=(
        "encapsulation_key", "decapsulation_key", "ciphertext",
        "public_key", "private_key", "signature",
    ))
    parser.add_argument("--parameter-set", action="append", help="exact parameter-set name")
    parser.add_argument("--json", action="store_true", help="emit stable machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        raw = _read_cli_input(args.input, args.encoding)
        matches = identify_pqc(
            raw,
            families=args.family,
            kinds=args.kind,
            parameter_sets=args.parameter_set,
        )
        if args.json:
            print(json.dumps({
                "length": len(raw),
                "ambiguous": len(matches) > 1,
                "matches": [pqc_object_to_dict(item) for item in matches],
            }, sort_keys=True, indent=2))
        elif not matches:
            print("no strict finalized-PQC interpretation")
        else:
            for item in matches:
                print(f"{item.standard} {item.parameter_set} {item.kind} ({item.length} bytes)")
            if len(matches) > 1:
                print(f"ambiguous: {len(matches)} valid interpretations")
        return 0 if matches else 1
    except PQCParseError as exc:
        print(f"cryptodepth_pqc: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # CLI boundary must not expose stdlib exception classes.
        print(f"cryptodepth_pqc: malformed input ({exc.__class__.__name__})", file=sys.stderr)
        return 2


__all__ = [
    "MAX_OBJECT_BYTES",
    "PQCParseError",
    "PQCField",
    "PQCObject",
    "parse_mlkem",
    "parse_mldsa",
    "parse_slhdsa",
    "parse_pqc",
    "identify_pqc",
    "pqc_object_to_dict",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
