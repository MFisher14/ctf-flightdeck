#!/usr/bin/env python3
"""Exact-verified signature-fault, MAC-misuse, and white-box crypto helpers.

The recovery functions in this module decline unless the computed secret is proved against the
supplied public key and every observation.  Payload-producing helpers return an explicit plan for
human review; they never contact an oracle or a judge.  The CLI reads one bounded local JSON object,
rejects duplicate members, and emits only JSON-serialisable evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from _shadowed import common_module

modern_crypto = common_module("modern_crypto")  # solvers/toolkits/modern_crypto.py wins a flat import


MAX_JSON = 2 * 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_OBSERVATIONS = 4096


@dataclass(frozen=True)
class SignatureFaultResult:
    private_scalar: int
    nonce: int
    curve: str
    verified: bool = True


@dataclass(frozen=True)
class Ed25519ReuseResult:
    secret_scalar: int
    nonce_scalar: int
    public_key_hex: str
    verified: bool = True


@dataclass(frozen=True)
class CBCMACForgeryPlan:
    candidate: bytes
    expected_tag: bytes
    assumptions: tuple[str, ...]
    algebra_verified: bool = True


def ecdsa_fault_pair_recover(curve: str, public_key, correct, faulty) -> SignatureFaultResult | None:
    """Recover an ECDSA scalar when a fault causes two valid signatures to reuse one nonce.

    ``correct`` and ``faulty`` are ``(r,s,z)`` triples.  A result is returned only after the shared
    nonce point has the supplied ``r``, both equations yield one scalar, and ``d*G`` equals the
    mandatory supplied public point.  This covers hash/message faults and deterministic-signer
    glitches that preserve ``k``; an arbitrary invalid faulty signature is not accepted.
    """
    try:
        r1, s1, z1 = (int(value) for value in correct)
        r2, s2, z2 = (int(value) for value in faulty)
        public = (int(public_key[0]), int(public_key[1]))
    except (TypeError, ValueError, IndexError):
        return None
    if r1 != r2 or z1 == z2 and s1 == s2:
        return None
    recovered = modern_crypto.ecdsa_nonce_reuse(r1, s1, z1, s2, z2, curve, public)
    if recovered is None:
        return None
    private, nonce, name = recovered
    cv = modern_crypto.CURVES.get(name)
    if cv is None or modern_crypto.ec_mul(private, cv) != public:
        return None
    # Re-enforce both signature equations after normalising the possible low-s representation.
    valid_equations = 0
    for written_s, z in ((s1, z1), (s2, z2)):
        for candidate_s in {written_s % cv["n"], (-written_s) % cv["n"]}:
            if candidate_s * nonce % cv["n"] == (z + r1 * private) % cv["n"]:
                valid_equations += 1
                break
    if valid_equations != 2:
        return None
    return SignatureFaultResult(private, nonce, name)


# Ed25519 arithmetic.  Extended coordinates avoid hundreds of inversions during scalar multiply.
_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, -1, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_ED_IDENTITY = (0, 1, 1, 0)
_ED_BASE = (_ED_BX, _ED_BY, 1, _ED_BX * _ED_BY % _ED_P)


def _ed_add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = 2 * _ED_D * t1 * t2 % _ED_P
    d = 2 * z1 * z2 % _ED_P
    e, f, g, h = (b - a) % _ED_P, (d - c) % _ED_P, (d + c) % _ED_P, (b + a) % _ED_P
    return e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P


def _ed_mul(scalar: int, point=_ED_BASE):
    scalar = int(scalar)
    if scalar < 0:
        raise ValueError("Ed25519 scalar must be non-negative")
    result, addend = _ED_IDENTITY, point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_affine(point):
    x, y, z, _t = point
    inverse = pow(z, -1, _ED_P)
    return x * inverse % _ED_P, y * inverse % _ED_P


def _ed_encode(point) -> bytes:
    x, y = _ed_affine(point)
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _ed_decode(encoded: bytes):
    if not isinstance(encoded, bytes) or len(encoded) != 32:
        return None
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    numerator = y * y - 1
    denominator = _ED_D * y * y + 1
    if denominator % _ED_P == 0:
        return None
    x2 = numerator * pow(denominator, -1, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P:
        x = x * _ED_I % _ED_P
    if (x * x - x2) % _ED_P or x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _ED_P - x
    point = (x, y, 1, x * y % _ED_P)
    if _ed_encode(point) != encoded:
        return None
    return point


def _ed_is_identity(point) -> bool:
    return _ed_affine(point) == (0, 1)


def _ed_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    a_point, r_point = _ed_decode(public), _ed_decode(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if a_point is None or r_point is None or scalar >= _ED_L:
        return False
    # Strict prime-subgroup verification avoids accepting a small-order ambiguity as a proof.
    if _ed_is_identity(a_point) or not _ed_is_identity(_ed_mul(_ED_L, a_point)):
        return False
    if not _ed_is_identity(_ed_mul(_ED_L, r_point)):
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _ED_L
    return _ed_encode(_ed_mul(scalar)) == _ed_encode(_ed_add(r_point, _ed_mul(challenge, a_point)))


def ed25519_nonce_reuse_recover(public_key: bytes, message1: bytes, signature1: bytes,
                                message2: bytes, signature2: bytes) -> Ed25519ReuseResult | None:
    """Recover an Ed25519 secret scalar from two exactly verified signatures sharing ``R``."""
    if not all(isinstance(value, bytes) for value in
               (public_key, message1, signature1, message2, signature2)):
        return None
    if (len(public_key) != 32 or len(signature1) != 64 or len(signature2) != 64
            or signature1[:32] != signature2[:32] or signature1 == signature2
            or len(message1) + len(message2) > MAX_BYTES):
        return None
    if not _ed_verify(public_key, message1, signature1) or not _ed_verify(public_key, message2, signature2):
        return None
    h1 = int.from_bytes(hashlib.sha512(signature1[:32] + public_key + message1).digest(), "little") % _ED_L
    h2 = int.from_bytes(hashlib.sha512(signature2[:32] + public_key + message2).digest(), "little") % _ED_L
    denominator = (h1 - h2) % _ED_L
    if denominator == 0:
        return None
    s1, s2 = int.from_bytes(signature1[32:], "little"), int.from_bytes(signature2[32:], "little")
    secret = (s1 - s2) * pow(denominator, -1, _ED_L) % _ED_L
    nonce = (s1 - h1 * secret) % _ED_L
    if (nonce + h2 * secret) % _ED_L != s2:
        return None
    if _ed_encode(_ed_mul(secret)) != public_key or _ed_encode(_ed_mul(nonce)) != signature1[:32]:
        return None
    return Ed25519ReuseResult(secret, nonce, public_key.hex())


def cbc_mac_length_extension(first_message: bytes, first_tag: bytes, second_message: bytes,
                             second_tag: bytes, *, block_size: int = 16) -> CBCMACForgeryPlan:
    """Build the classic variable-length, zero-IV raw CBC-MAC extension for human review.

    The transformation is an algebraic identity only under the stated assumptions.  It deliberately
    does not label a remote construction vulnerable or claim that a candidate was accepted.
    """
    values = (first_message, first_tag, second_message, second_tag)
    if not all(isinstance(value, bytes) for value in values):
        raise TypeError("CBC-MAC inputs must be bytes")
    if not 2 <= block_size <= 255 or len(first_tag) != block_size or len(second_tag) != block_size:
        raise ValueError("CBC-MAC tags must each be exactly one block")
    if (not first_message or not second_message or len(first_message) % block_size
            or len(second_message) % block_size or sum(map(len, values)) > MAX_BYTES):
        raise ValueError("CBC-MAC messages must be bounded, non-empty, and block aligned")
    bridge = bytes(a ^ b for a, b in zip(second_message[:block_size], first_tag))
    candidate = first_message + bridge + second_message[block_size:]
    return CBCMACForgeryPlan(
        candidate, second_tag,
        ("raw CBC-MAC", "fixed all-zero IV", "same key", "no length binding or finalisation"),
    )


def verify_cbc_mac_plan(plan: CBCMACForgeryPlan, mac: Callable[[bytes], bytes]) -> bool:
    """Verify a plan with a caller-supplied local MAC function; exceptions are a clean decline."""
    if not isinstance(plan, CBCMACForgeryPlan) or not callable(mac):
        return False
    try:
        actual = mac(plan.candidate)
    except Exception:
        return False
    return isinstance(actual, bytes) and actual == plan.expected_tag


def audit_aead_misuse(observations) -> dict[str, Any]:
    """Group bounded observations and report nonce reuse/tag truncation without inventing a key."""
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ValueError(f"observations must be a list of at most {MAX_OBSERVATIONS} entries")
    rows, groups, total = [], {}, 0
    for index, item in enumerate(observations):
        if not isinstance(item, dict):
            raise ValueError(f"observation {index} must be an object")
        algorithm, key_id, nonce = item.get("algorithm"), item.get("key_id"), item.get("nonce")
        if not all(isinstance(value, str) and 0 < len(value) <= 256
                   for value in (algorithm, key_id, nonce)):
            raise ValueError(f"observation {index} needs bounded algorithm/key_id/nonce strings")
        ciphertext, tag = item.get("ciphertext", ""), item.get("tag", "")
        if not isinstance(ciphertext, str) or not isinstance(tag, str):
            raise ValueError("ciphertext/tag must be hexadecimal strings")
        try:
            ciphertext_raw, tag_raw, nonce_raw = bytes.fromhex(ciphertext), bytes.fromhex(tag), bytes.fromhex(nonce)
        except ValueError as exc:
            raise ValueError("nonce/ciphertext/tag must be even-length hexadecimal") from exc
        total += len(ciphertext_raw) + len(tag_raw) + len(nonce_raw)
        if total > MAX_BYTES:
            raise ValueError("AEAD observations exceed the byte cap")
        row = {"index": index, "algorithm": algorithm.upper(), "key_id": key_id,
               "nonce": nonce_raw.hex(), "ciphertext_bytes": len(ciphertext_raw),
               "tag_bits": len(tag_raw) * 8}
        rows.append(row)
        groups.setdefault((key_id, algorithm.upper(), nonce_raw), []).append(row)
    findings = []
    for (key_id, algorithm, nonce), group in groups.items():
        if len(group) > 1:
            severity = "informational" if "SIV" in algorithm else "critical"
            findings.append({"kind": "nonce_reuse", "severity": severity, "algorithm": algorithm,
                             "key_id": key_id, "nonce": nonce.hex(),
                             "indices": [row["index"] for row in group],
                             "next_engine": (None if "SIV" in algorithm else "crypto_depth.py")})
    for row in rows:
        expected = 128 if any(name in row["algorithm"] for name in ("GCM", "POLY1305")) else None
        if expected is not None and row["tag_bits"] < expected:
            findings.append({"kind": "truncated_tag", "severity": "high", "index": row["index"],
                             "tag_bits": row["tag_bits"], "expected_bits": expected})
    return {"observations": rows, "findings": findings, "verified": True,
            "offline": True, "requests_sent": 0}


def _aes_sbox(value: int) -> int:
    inverse = 0
    # Python modular exponentiation is integer-ring arithmetic, not GF(2^8); compute the inverse.
    if value:
        result, base, exponent = 1, value, 254
        while exponent:
            if exponent & 1:
                result = _gf256_mul(result, base)
            base = _gf256_mul(base, base)
            exponent >>= 1
        inverse = result
    rotated = lambda byte, shift: ((byte << shift) | (byte >> (8 - shift))) & 0xFF
    return inverse ^ rotated(inverse, 1) ^ rotated(inverse, 2) ^ rotated(inverse, 3) ^ rotated(inverse, 4) ^ 0x63


def _gf256_mul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        high = left & 0x80
        left = (left << 1) & 0xFF
        if high:
            left ^= 0x1B
        right >>= 1
    return result


_AES_SBOX = bytes(_aes_sbox(value) for value in range(256))


def recover_masked_aes_sbox(table: bytes) -> list[dict[str, int]]:
    """Find every exact ``T[x] = AES_SBOX[x xor k] xor mask`` explanation of a 256-byte table."""
    if not isinstance(table, bytes) or len(table) != 256:
        raise ValueError("masked AES S-box table must contain exactly 256 bytes")
    candidates = []
    for key_xor in range(256):
        output_xor = table[0] ^ _AES_SBOX[key_xor]
        if all(table[value] == (_AES_SBOX[value ^ key_xor] ^ output_xor) for value in range(256)):
            candidates.append({"input_xor": key_xor, "output_xor": output_xor})
    return candidates


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def parse_json_document(raw: bytes) -> dict[str, Any]:
    """Parse one bounded strict JSON object for CLI and deterministic mutation tests."""
    if not isinstance(raw, bytes) or len(raw) > MAX_JSON:
        raise ValueError("input JSON must be bounded bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(
                               f"non-finite JSON number {value!r}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("input is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def _load(path_value: str) -> dict[str, Any]:
    path = Path(path_value)
    if not path.is_file() or path.stat().st_size > MAX_JSON:
        raise ValueError("input JSON is absent or over the size cap")
    return parse_json_document(path.read_bytes())


def _hex(value: Any, name: str, limit: int = MAX_BYTES) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2:
        raise ValueError(f"{name} must be bounded hexadecimal")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be even-length hexadecimal") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="crypto_faults.py")
    parser.add_argument("operation", choices=("ecdsa-fault", "ed25519-reuse", "cbc-mac",
                                              "aead-audit", "whitebox-sbox"))
    parser.add_argument("input")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        data = _load(args.input)
        if args.operation == "ecdsa-fault":
            result = ecdsa_fault_pair_recover(data["curve"], data["public_key"],
                                               data["correct"], data["faulty"])
            if result is None:
                raise ValueError("no exactly verified ECDSA fault recovery")
            output = asdict(result)
        elif args.operation == "ed25519-reuse":
            result = ed25519_nonce_reuse_recover(
                _hex(data["public_key"], "public_key", 32),
                _hex(data["message1"], "message1"), _hex(data["signature1"], "signature1", 64),
                _hex(data["message2"], "message2"), _hex(data["signature2"], "signature2", 64),
            )
            if result is None:
                raise ValueError("no exactly verified Ed25519 nonce-reuse recovery")
            output = asdict(result)
        elif args.operation == "cbc-mac":
            plan = cbc_mac_length_extension(
                _hex(data["first_message"], "first_message"), _hex(data["first_tag"], "first_tag"),
                _hex(data["second_message"], "second_message"), _hex(data["second_tag"], "second_tag"),
                block_size=data.get("block_size", 16),
            )
            output = {**asdict(plan), "candidate": plan.candidate.hex(),
                      "expected_tag": plan.expected_tag.hex()}
        elif args.operation == "aead-audit":
            output = audit_aead_misuse(data.get("observations"))
        else:
            candidates = recover_masked_aes_sbox(_hex(data["table"], "table", 256))
            output = {"candidates": candidates, "verified": True}
        print(json.dumps(output, sort_keys=True, indent=2 if args.json else None))
        return 0
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"crypto_faults: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
