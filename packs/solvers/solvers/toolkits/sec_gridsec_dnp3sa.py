#!/usr/bin/env python3
"""Passive DNP3 Secure Authentication and ICCP/TASE.2 evidence analyzer.

This module consumes complete, already-reassembled DNP3 application fragments,
Group-120 object streams, or supplied ICCP/MMS bytes.  It never opens a socket,
sends a frame, changes a key, or executes a decoded control operation.

DNP3 Secure Authentication v2/v5 object layouts follow IEEE 1815 Annex A.45.
Generic DNP link/capture processing already lives in ``ics_protocols`` and
``ics_capture``; generic MMS/ACSE/presentation decoding is delegated to
``ot_mms_services``.  DNP3 Security Layer (formerly SAv6) has no stable public
DNP-specific byte grammar, so bytes explicitly identified by capture metadata
can only be fingerprinted and reported as opaque.

Every public parser/verifier raises only :class:`GridDNP3SAError` on invalid,
unsupported, or excessive input.
"""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import hmac
import json
from pathlib import Path
import sys
from typing import Any, Callable


MAX_INPUT = 1 << 20
MAX_OBJECTS = 1024
MAX_TEXT = 65535


class GridDNP3SAError(ValueError):
    """Malformed, unsupported, ambiguous, or excessive grid-security input."""


def _guard(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except GridDNP3SAError:
            raise
        except Exception as exc:
            raise GridDNP3SAError(
                f"{function.__name__}: {type(exc).__name__}"
            ) from None

    return guarded


def _blob(value: Any, *, name: str = "input", allow_empty: bool = False) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise GridDNP3SAError(f"{name} must be bytes-like")
    if isinstance(value, memoryview) and (value.ndim != 1 or not value.contiguous):
        raise GridDNP3SAError(f"{name} memoryview must be contiguous and one-dimensional")
    size = value.nbytes if isinstance(value, memoryview) else len(value)
    if size > MAX_INPUT or (not allow_empty and size == 0):
        raise GridDNP3SAError(f"{name} is empty or exceeds the size cap")
    try:
        data = bytes(value)
    except Exception as exc:
        raise GridDNP3SAError(f"{name} is not a contiguous byte buffer") from None
    if len(data) != size:
        raise GridDNP3SAError(f"{name} byte length is ambiguous")
    return data


def _need(data: bytes, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise GridDNP3SAError(f"truncated {what}")


def _u16(data: bytes, offset: int) -> int:
    _need(data, offset, 2, "uint16")
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    _need(data, offset, 4, "uint32")
    return int.from_bytes(data[offset : offset + 4], "little")


VARIATION_NAMES = {
    1: "Challenge",
    2: "Reply",
    3: "AggressiveModeRequest",
    4: "SessionKeyStatusRequest",
    5: "SessionKeyStatus",
    6: "SessionKeyChange",
    7: "Error",
    8: "UserCertificate",
    9: "AggressiveModeMAC",
    10: "UserStatusChange",
    11: "UpdateKeyChangeRequest",
    12: "UpdateKeyChangeReply",
    13: "UpdateKeyChange",
    14: "UpdateKeyChangeSignature",
    15: "UpdateKeyChangeConfirmation",
}

MAC_ALGORITHMS = {
    0: {"name": "none", "digest": None, "length": 0},
    1: {"name": "hmac-sha1-4", "digest": "sha1", "length": 4},
    2: {"name": "hmac-sha1-10", "digest": "sha1", "length": 10},
    3: {"name": "hmac-sha256-8", "digest": "sha256", "length": 8},
    4: {"name": "hmac-sha256-16", "digest": "sha256", "length": 16},
    5: {"name": "hmac-sha1-8", "digest": "sha1", "length": 8},
    6: {"name": "aes-gmac-12", "digest": "gmac", "length": 12},
}

CHALLENGE_REASONS = {0: "not-used", 1: "critical-function"}
KEY_WRAP_ALGORITHMS = {0: "not-used", 1: "aes-128-rfc3394", 2: "aes-256-rfc3394"}
KEY_CHANGE_METHODS = {
    3: {
        "name": "symmetric-aes128-wrap-sha1-hmac",
        "authentication": "sha1-hmac",
        "master_challenge_length": 20,
        "outstation_challenge_length": 20,
    },
    4: {
        "name": "symmetric-aes256-wrap-sha256-hmac",
        "authentication": "sha256-hmac",
        "master_challenge_length": 32,
        "outstation_challenge_length": 32,
    },
    5: {
        "name": "symmetric-aes256-wrap-aes-gmac",
        "authentication": "aes-gmac",
        "master_challenge_length": 32,
        "outstation_challenge_length": 32,
    },
    67: {
        "name": "asymmetric-rsa1024-dsa-sha1-hmac",
        "authentication": "sha1-hmac",
        "master_challenge_length": 0,
        "outstation_challenge_length": 20,
    },
    68: {
        "name": "asymmetric-rsa2048-dsa-sha256-hmac",
        "authentication": "sha256-hmac",
        "master_challenge_length": 0,
        "outstation_challenge_length": 32,
    },
    69: {
        "name": "asymmetric-rsa3072-dsa-sha256-hmac",
        "authentication": "sha256-hmac",
        "master_challenge_length": 0,
        "outstation_challenge_length": 32,
    },
    70: {
        "name": "asymmetric-rsa2048-dsa-aes-gmac",
        "authentication": "aes-gmac",
        "master_challenge_length": 0,
        "outstation_challenge_length": 32,
    },
    71: {
        "name": "asymmetric-rsa3072-dsa-aes-gmac",
        "authentication": "aes-gmac",
        "master_challenge_length": 0,
        "outstation_challenge_length": 32,
    },
}
KEY_STATUSES = {
    0: "not-used",
    1: "ok",
    2: "not-initialized",
    3: "communication-failure",
    4: "authentication-failure",
}
ERROR_CODES = {
    0: "not-used",
    1: "authentication-failed",
    2: "unexpected-reply",
    3: "no-reply",
    4: "aggressive-mode-not-supported",
    5: "mac-algorithm-not-supported",
    6: "key-wrap-algorithm-not-supported",
    7: "authorization-failed",
    8: "update-key-change-method-not-permitted",
    9: "invalid-signature",
    10: "invalid-certification-data",
    11: "unknown-user",
    12: "maximum-session-key-status-requests",
}


def _version_evidence(variation: int, algorithm: int | None = None) -> dict[str, Any]:
    if variation in {8, 10, 11, 12, 13, 14, 15}:
        return {
            "classification": "sav5-feature",
            "note": "this variation was added by Secure Authentication v5",
        }
    if algorithm == 1:
        return {
            "classification": "sav2-only-algorithm",
            "note": "MAC algorithm 1 is explicitly retained for SAv2 only",
        }
    return {
        "classification": "sav2-or-sav5-compatible",
        "note": "the object alone is not a reliable SAv2/SAv5 discriminator",
    }


def _method_kind(method: int) -> str:
    if method < 64:
        return "symmetric"
    if method < 128:
        return "asymmetric"
    return "reserved-or-vendor"


def _key_change_method(method: Any) -> dict[str, Any]:
    if not isinstance(method, int) or isinstance(method, bool):
        raise GridDNP3SAError("key-change method context must be an integer")
    info = KEY_CHANGE_METHODS.get(method)
    if info is None:
        raise GridDNP3SAError(
            f"unsupported, obsolete, or reserved key-change method {method}"
        )
    return info


def _challenge_length_validation(
    actual: int, key_change_method: int | None
) -> dict[str, Any]:
    if actual not in {20, 32}:
        raise GridDNP3SAError(
            "update-key challenge length is not valid for any standardized method"
        )
    if key_change_method is None:
        return {
            "status": "requires-key-change-method-context",
            "actual": actual,
            "standardized_lengths": [20, 32],
            "note": (
                "g120v12 does not carry the method; validate it against the preceding "
                "g120v11 or configured association method"
            ),
        }
    info = _key_change_method(key_change_method)
    expected = int(info["outstation_challenge_length"])
    if actual != expected:
        raise GridDNP3SAError(
            f"challenge length {actual} does not match key-change method "
            f"{key_change_method} ({expected} required)"
        )
    return {
        "status": "validated",
        "key_change_method": key_change_method,
        "key_change_method_name": info["name"],
        "authentication": info["authentication"],
        "expected": expected,
        "actual": actual,
    }


def _decode_utf8(raw: bytes, what: str) -> str:
    if len(raw) > MAX_TEXT:
        raise GridDNP3SAError(f"{what} exceeds text cap")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise GridDNP3SAError(f"{what} is not valid UTF-8") from None


def _mac_length(algorithm: int, *, permit_none: bool = False) -> int:
    if algorithm not in MAC_ALGORITHMS or (algorithm == 0 and not permit_none):
        raise GridDNP3SAError(f"unsupported MAC algorithm {algorithm}")
    return int(MAC_ALGORITHMS[algorithm]["length"])


def _parse_sa_object(
    variation: int, value: bytes, *, key_change_method: int | None = None
) -> dict[str, Any]:
    if variation not in VARIATION_NAMES:
        raise GridDNP3SAError("DNP3 SA variation must be in 1..15")
    value = _blob(value, name="object value")
    out: dict[str, Any] = {
        "group": 120,
        "variation": variation,
        "variation_name": VARIATION_NAMES[variation],
        "raw_hex": value.hex(),
    }
    algorithm: int | None = None

    if variation == 1:
        _need(value, 0, 12, "Challenge object and four-byte challenge")
        out.update(
            sequence=_u32(value, 0),
            user=_u16(value, 4),
            mac_algorithm=value[6],
            reason=value[7],
            challenge_hex=value[8:].hex(),
        )
        algorithm = value[6]
        _mac_length(algorithm)
        out["mac_algorithm_name"] = MAC_ALGORITHMS[algorithm]["name"]
        out["reason_name"] = CHALLENGE_REASONS.get(value[7], "reserved")
        if value[7] not in CHALLENGE_REASONS:
            out["reserved_reason"] = True
    elif variation == 2:
        _need(value, 0, 10, "Reply object and minimum four-octet MAC")
        out.update(sequence=_u32(value, 0), user=_u16(value, 4), mac_hex=value[6:].hex())
    elif variation == 3:
        if len(value) != 6:
            raise GridDNP3SAError("AggressiveModeRequest must contain CSQ and user only")
        out.update(sequence=_u32(value, 0), user=_u16(value, 4))
    elif variation == 4:
        if len(value) != 2:
            raise GridDNP3SAError("SessionKeyStatusRequest must contain one user number")
        out["user"] = _u16(value, 0)
    elif variation == 5:
        _need(value, 0, 11, "SessionKeyStatus object")
        challenge_length = _u16(value, 9)
        if challenge_length > len(value) - 11:
            raise GridDNP3SAError("SessionKeyStatus challenge length exceeds object")
        algorithm = value[8]
        expected_mac = _mac_length(algorithm, permit_none=True)
        if len(value) != 11 + challenge_length + expected_mac:
            raise GridDNP3SAError("SessionKeyStatus challenge/MAC lengths are inconsistent")
        challenge = value[11 : 11 + challenge_length]
        mac = value[11 + challenge_length :]
        if algorithm != 0 and challenge_length < 4:
            raise GridDNP3SAError("SessionKeyStatus challenge is shorter than four octets")
        out.update(
            sequence=_u32(value, 0),
            user=_u16(value, 4),
            key_wrap_algorithm=value[6],
            key_wrap_algorithm_name=KEY_WRAP_ALGORITHMS.get(value[6], "reserved-or-vendor"),
            key_status=value[7],
            key_status_name=KEY_STATUSES.get(value[7], "reserved"),
            mac_algorithm=algorithm,
            mac_algorithm_name=MAC_ALGORITHMS[algorithm]["name"],
            challenge_length=challenge_length,
            challenge_hex=challenge.hex(),
            mac_hex=mac.hex(),
            authenticated_prefix_hex=value[: 11 + challenge_length].hex(),
        )
    elif variation == 6:
        _need(value, 0, 30, "SessionKeyChange object and wrapped key data")
        wrapped = value[6:]
        if len(wrapped) < 24 or len(wrapped) % 8:
            raise GridDNP3SAError("wrapped session-key data is not RFC 3394 sized")
        out.update(
            sequence=_u32(value, 0),
            user=_u16(value, 4),
            wrapped_key_data_hex=wrapped.hex(),
        )
    elif variation == 7:
        _need(value, 0, 15, "Error object")
        text = value[15:]
        out.update(
            sequence=_u32(value, 0),
            user=_u16(value, 4),
            association_id=_u16(value, 6),
            error_code=value[8],
            error_name=ERROR_CODES.get(value[8], "reserved-or-vendor"),
            time_unix_ms=int.from_bytes(value[9:15], "little"),
            error_text=_decode_utf8(text, "error text") if text else "",
        )
    elif variation == 8:
        _need(value, 0, 3, "UserCertificate object")
        if value[0] < 64 or value[1] not in {1, 2}:
            raise GridDNP3SAError(
                "UserCertificate requires an asymmetric method and ID/attribute certificate"
            )
        out.update(
            key_change_method=value[0],
            key_change_method_kind=_method_kind(value[0]),
            certificate_type=value[1],
            certificate_hex=value[2:].hex(),
        )
    elif variation == 9:
        if not 1 <= len(value) <= 64:
            raise GridDNP3SAError("AggressiveModeMAC has an invalid length")
        out["mac_hex"] = value.hex()
    elif variation == 10:
        _need(value, 0, 16, "UserStatusChange header")
        username_length = _u16(value, 10)
        public_key_length = _u16(value, 12)
        certification_length = _u16(value, 14)
        total = 16 + username_length + public_key_length + certification_length
        if len(value) != total:
            raise GridDNP3SAError("UserStatusChange component lengths are inconsistent")
        operation = value[1]
        if operation not in {1, 2, 3}:
            raise GridDNP3SAError("UserStatusChange operation is reserved")
        at = 16
        username = value[at : at + username_length]
        at += username_length
        public_key = value[at : at + public_key_length]
        at += public_key_length
        certification = value[at:]
        out.update(
            key_change_method=value[0],
            key_change_method_kind=_method_kind(value[0]),
            operation=operation,
            operation_name={1: "add", 2: "delete", 3: "change"}[operation],
            status_change_sequence=_u32(value, 2),
            user_role=_u16(value, 6),
            role_expiry_interval=_u16(value, 8),
            username=_decode_utf8(username, "username"),
            public_key_hex=public_key.hex(),
            certification_data_hex=certification.hex(),
        )
    elif variation == 11:
        _need(value, 0, 6, "UpdateKeyChangeRequest header and username")
        method = value[0]
        method_info = _key_change_method(method)
        username_length = _u16(value, 1)
        challenge_length = _u16(value, 3)
        if (
            username_length == 0
            or len(value) != 5 + username_length + challenge_length
        ):
            raise GridDNP3SAError("UpdateKeyChangeRequest lengths are inconsistent")
        expected_challenge_length = int(method_info["master_challenge_length"])
        if challenge_length != expected_challenge_length:
            raise GridDNP3SAError(
                f"master challenge length {challenge_length} does not match "
                f"key-change method {method} ({expected_challenge_length} required)"
            )
        challenge_validation = {
            "status": "validated",
            "key_change_method": method,
            "key_change_method_name": method_info["name"],
            "authentication": method_info["authentication"],
            "expected": expected_challenge_length,
            "actual": challenge_length,
        }
        username = value[5 : 5 + username_length]
        challenge = value[5 + username_length :]
        out.update(
            key_change_method=method,
            key_change_method_name=method_info["name"],
            key_change_method_kind=_method_kind(method),
            username=_decode_utf8(username, "username"),
            challenge_length=challenge_length,
            master_challenge_hex=challenge.hex(),
            challenge_length_validation=challenge_validation,
        )
    elif variation == 12:
        _need(value, 0, 12, "UpdateKeyChangeReply and challenge")
        challenge_length = _u16(value, 6)
        if len(value) != 8 + challenge_length:
            raise GridDNP3SAError("UpdateKeyChangeReply lengths are inconsistent")
        challenge_validation = _challenge_length_validation(
            challenge_length, key_change_method
        )
        out.update(
            sequence=_u32(value, 0),
            user=_u16(value, 4),
            challenge_length=challenge_length,
            outstation_challenge_hex=value[8:].hex(),
            challenge_length_validation=challenge_validation,
        )
    elif variation == 13:
        _need(value, 0, 9, "UpdateKeyChange data")
        encrypted_length = _u16(value, 6)
        if len(value) != 8 + encrypted_length or encrypted_length == 0:
            raise GridDNP3SAError("UpdateKeyChange encrypted-data length is inconsistent")
        out.update(
            sequence=_u32(value, 0),
            user=_u16(value, 4),
            encrypted_update_key_hex=value[8:].hex(),
        )
    elif variation == 14:
        if not 1 <= len(value) <= MAX_TEXT:
            raise GridDNP3SAError("UpdateKeyChangeSignature is empty or excessive")
        out["signature_hex"] = value.hex()
    elif variation == 15:
        if not 1 <= len(value) <= 64:
            raise GridDNP3SAError("UpdateKeyChangeConfirmation MAC has an invalid length")
        out["mac_hex"] = value.hex()

    out["version_evidence"] = _version_evidence(variation, algorithm)
    return out


@_guard
def parse_sa_object(
    variation: int, value: bytes, *, key_change_method: int | None = None
) -> dict[str, Any]:
    """Parse one Group-120 object body using its published variation layout."""
    if not isinstance(variation, int) or isinstance(variation, bool):
        raise GridDNP3SAError("variation must be an integer")
    return _parse_sa_object(
        variation, value, key_change_method=key_change_method
    )


def _parse_one_object(
    data: bytes, offset: int, *, key_change_method: int | None = None
) -> tuple[dict[str, Any], int]:
    _need(data, offset, 4, "DNP3 SA object header/count")
    start = offset
    group, variation, qualifier, count = data[offset : offset + 4]
    offset += 4
    if group != 120 or variation not in VARIATION_NAMES:
        raise GridDNP3SAError("object stream contains a non-Group-120 object")
    if count != 1:
        raise GridDNP3SAError("DNP3 SA object count must be one")
    if qualifier == 0x5B and variation not in {3, 4}:
        _need(data, offset, 2, "free-format object size")
        size = _u16(data, offset)
        offset += 2
        if size == 0 or size > MAX_INPUT:
            raise GridDNP3SAError("free-format object size is invalid")
    elif qualifier == 0x07 and variation in {3, 4}:
        size = 6 if variation == 3 else 2
    else:
        raise GridDNP3SAError("unexpected qualifier for DNP3 SA variation")
    _need(data, offset, size, "DNP3 SA object value")
    value_offset = offset
    parsed = _parse_sa_object(
        variation,
        data[offset : offset + size],
        key_change_method=key_change_method,
    )
    offset += size
    parsed.update(
        qualifier=qualifier,
        count=count,
        object_size=size,
        header_offset=start,
        value_offset=value_offset,
        end_offset=offset,
        encoded_hex=data[start:offset].hex(),
    )
    return parsed, offset


def _parse_object_stream(
    data: bytes, *, key_change_method: int | None = None
) -> list[dict[str, Any]]:
    offset = 0
    objects: list[dict[str, Any]] = []
    while offset < len(data):
        if len(objects) >= MAX_OBJECTS:
            raise GridDNP3SAError("DNP3 SA object count exceeds cap")
        parsed, offset = _parse_one_object(
            data, offset, key_change_method=key_change_method
        )
        objects.append(parsed)
    if not objects:
        raise GridDNP3SAError("empty DNP3 SA object stream")
    return objects


@_guard
def parse_sa_object_stream(
    data: bytes, *, key_change_method: int | None = None
) -> list[dict[str, Any]]:
    """Parse Group-120 object headers/values without an application header."""
    return _parse_object_stream(
        _blob(data, name="object stream"), key_change_method=key_change_method
    )


def _application_header(fragment: bytes) -> tuple[dict[str, Any], int]:
    _need(fragment, 0, 2, "DNP3 application header")
    control, function = fragment[0], fragment[1]
    if control & 0xC0 != 0xC0:
        raise GridDNP3SAError("input is not one complete FIR/FIN application fragment")
    response = bool(function & 0x80)
    body_offset = 4 if response else 2
    _need(fragment, 0, body_offset, "DNP3 response IIN")
    header: dict[str, Any] = {
        "control": control,
        "fir": bool(control & 0x80),
        "fin": bool(control & 0x40),
        "confirm": bool(control & 0x20),
        "unsolicited": bool(control & 0x10),
        "application_sequence": control & 0x0F,
        "function": function,
        "function_name": {
            0x00: "confirm",
            0x20: "authentication-request",
            0x21: "authentication-error-no-ack",
            0x81: "response",
            0x82: "unsolicited-response",
            0x83: "authentication-response",
        }.get(function, f"function-0x{function:02x}"),
        "response": response,
    }
    if response:
        header["iin"] = int.from_bytes(fragment[2:4], "little")
    return header, body_offset


def _aggressive_objects(fragment: bytes, body_offset: int) -> tuple[list[dict[str, Any]], bytes, int]:
    body = fragment[body_offset:]
    first, next_offset = _parse_one_object(body, 0)
    if first["variation"] != 3 or next_offset != 10:
        raise GridDNP3SAError("aggressive fragment must begin with fixed g120v3")
    candidates: list[tuple[int, dict[str, Any]]] = []
    for offset in range(next_offset, max(next_offset, len(body) - 5)):
        if body[offset : offset + 4] != b"\x78\x09\x5b\x01":
            continue
        if offset + 6 > len(body):
            continue
        size = _u16(body, offset + 4)
        if size and offset + 6 + size == len(body):
            parsed = _parse_sa_object(9, body[offset + 6 :])
            parsed.update(
                qualifier=0x5B,
                count=1,
                object_size=size,
                header_offset=body_offset + offset,
                value_offset=body_offset + offset + 6,
                end_offset=len(fragment),
                encoded_hex=body[offset:].hex(),
            )
            candidates.append((offset, parsed))
    if len(candidates) != 1:
        raise GridDNP3SAError("aggressive fragment has no unique trailing g120v9")
    mac_header_offset, mac = candidates[0]
    first = dict(first)
    for key in ("header_offset", "value_offset", "end_offset"):
        first[key] += body_offset
    ordinary = body[next_offset:mac_header_offset]
    return [first, mac], ordinary, body_offset + mac_header_offset + 6


def _ordinary_response_objects(
    fragment: bytes, body_offset: int, challenge_offset: int
) -> list[dict[str, Any]]:
    """Strictly validate the ordinary prefix using the repository DNP object parser."""
    ordinary = fragment[body_offset:challenge_offset]
    if not ordinary:
        raise GridDNP3SAError(
            "Request Secure Confirmation must follow ordinary response objects"
        )
    try:
        import ics_protocols

        decoded = ics_protocols.parse_dnp3_application(
            fragment[:body_offset] + ordinary
        )
    except Exception:
        raise GridDNP3SAError(
            "ordinary Request Secure Confirmation prefix is not a bounded DNP3 object stream"
        ) from None
    application = decoded.get("application") if isinstance(decoded, dict) else None
    objects = application.get("objects") if isinstance(application, dict) else None
    if not isinstance(objects, list) or not objects:
        raise GridDNP3SAError(
            "Request Secure Confirmation has no decoded ordinary response objects"
        )
    for item in objects:
        if (
            not isinstance(item, dict)
            or item.get("group") == 120
            or "undecoded" in item
            or (not item.get("points") and "packed" not in item)
        ):
            raise GridDNP3SAError(
                "ordinary Request Secure Confirmation prefix is ambiguous or unsupported"
            )
    return objects


def _secure_confirmation_objects(
    fragment: bytes, body_offset: int
) -> tuple[list[dict[str, Any]], bytes, list[dict[str, Any]]]:
    """Find one trailing g120v1 only after a fully decoded ordinary response."""
    body = fragment[body_offset:]
    marker = b"\x78\x01\x5b\x01"
    candidates: list[tuple[dict[str, Any], int, list[dict[str, Any]]]] = []
    for offset in range(1, max(1, len(body) - 5)):
        if body[offset : offset + 4] != marker or offset + 6 > len(body):
            continue
        size = _u16(body, offset + 4)
        if size == 0 or offset + 6 + size != len(body):
            continue
        try:
            challenge, end = _parse_one_object(body, offset)
            ordinary_objects = _ordinary_response_objects(
                fragment, body_offset, body_offset + offset
            )
        except GridDNP3SAError:
            continue
        if end == len(body) and challenge.get("variation") == 1:
            candidates.append((challenge, offset, ordinary_objects))
    if len(candidates) != 1:
        raise GridDNP3SAError(
            "response has no unique, structurally bounded trailing g120v1"
        )
    challenge, offset, ordinary_objects = candidates[0]
    challenge = dict(challenge)
    for key in ("header_offset", "value_offset", "end_offset"):
        challenge[key] += body_offset
    return [challenge], body[:offset], ordinary_objects


def _validate_function_and_order(
    function: int,
    variations: list[int],
    aggressive: bool,
    *,
    secure_confirmation: bool = False,
) -> None:
    if secure_confirmation:
        if function not in {0x81, 0x82} or variations != [1]:
            raise GridDNP3SAError("invalid Request Secure Confirmation response")
        return
    if aggressive:
        if variations != [3, 9] or function in {0x20, 0x21, 0x83}:
            raise GridDNP3SAError("invalid aggressive-mode variation order/function")
        if not (function <= 0x1F or function in {0x81, 0x82}):
            raise GridDNP3SAError("aggressive mode wraps only ordinary requests/responses")
        return
    allowed_sequences = {
        (variation,) for variation in VARIATION_NAMES if variation not in {3, 9, 13, 14}
    }
    allowed_sequences.update({(13, 14), (13, 15)})
    sequence = tuple(variations)
    if sequence not in allowed_sequences:
        raise GridDNP3SAError("invalid standalone/paired DNP3 SA object order")
    allowed_functions = {
        1: {0x20, 0x83},
        2: {0x20, 0x83},
        4: {0x20},
        5: {0x83},
        6: {0x20},
        7: {0x21, 0x83},
        8: {0x20},
        10: {0x20},
        11: {0x20},
        12: {0x83},
        13: {0x20},
        15: {0x20, 0x83},
    }
    for variation in variations:
        if function not in allowed_functions.get(variation, {0x20}):
            raise GridDNP3SAError(
                f"function 0x{function:02x} is invalid for g120v{variation}"
            )


def _parse_fragment(
    fragment: bytes, *, key_change_method: int | None = None
) -> dict[str, Any]:
    header, body_offset = _application_header(fragment)
    body = fragment[body_offset:]
    if not body:
        raise GridDNP3SAError("application fragment has no authentication objects")
    aggressive = body.startswith(b"\x78\x03\x07\x01")
    secure_confirmation = False
    ordinary_response_objects: list[dict[str, Any]] = []
    if aggressive:
        objects, ordinary, mac_value_offset = _aggressive_objects(fragment, body_offset)
    elif int(header["function"]) in {0x81, 0x82} and not body.startswith(b"\x78"):
        if not header["confirm"]:
            raise GridDNP3SAError(
                "Request Secure Confirmation response must set the CON bit"
            )
        if bool(header["unsolicited"]) != (int(header["function"]) == 0x82):
            raise GridDNP3SAError(
                "response function and application UNS bit are inconsistent"
            )
        objects, ordinary, ordinary_response_objects = _secure_confirmation_objects(
            fragment, body_offset
        )
        secure_confirmation = True
        mac_value_offset = -1
    else:
        objects = _parse_object_stream(body, key_change_method=key_change_method)
        ordinary = b""
        for item in objects:
            for key in ("header_offset", "value_offset", "end_offset"):
                item[key] += body_offset
        mac_value_offset = -1
    variations = [int(item["variation"]) for item in objects]
    _validate_function_and_order(
        int(header["function"]),
        variations,
        aggressive,
        secure_confirmation=secure_confirmation,
    )
    version_evidence = sorted({item["version_evidence"]["classification"] for item in objects})
    result: dict[str, Any] = {
        "protocol": "dnp3-secure-authentication",
        "application": header,
        "objects": objects,
        "aggressive_mode": aggressive,
        "request_secure_confirmation": secure_confirmation,
        "version_evidence": version_evidence,
        "version_caveat": (
            "core g120 objects do not by themselves distinguish SAv2 from SAv5; "
            "SAv2 and SAv5 unsolicited sequence rules also differ"
        ),
        "dnp3_security_layer": {
            "name": "DNP3-SL (formerly SAv6)",
            "recognized_from_this_fragment": False,
            "note": "DNP3-SL is a separate session layer, not Group-120 SAv5 syntax",
        },
    }
    if aggressive:
        result["ordinary_objects_hex"] = ordinary.hex()
        result["mac_value_offset"] = mac_value_offset
    elif secure_confirmation:
        result["ordinary_objects_hex"] = ordinary.hex()
        result["ordinary_response_objects"] = ordinary_response_objects
    return result


@_guard
def parse_dnp3_sa_fragment(
    fragment: bytes, *, key_change_method: int | None = None
) -> dict[str, Any]:
    """Parse one complete DNP application fragment containing SA objects."""
    return _parse_fragment(
        _blob(fragment, name="application fragment"),
        key_change_method=key_change_method,
    )


def _algorithm_id(algorithm: int | str) -> int:
    if isinstance(algorithm, bool):
        raise GridDNP3SAError("invalid MAC algorithm")
    if isinstance(algorithm, int):
        number = algorithm
    elif isinstance(algorithm, str):
        normalized = algorithm.strip().lower().replace("_", "-")
        aliases = {str(number): number for number in MAC_ALGORITHMS}
        aliases.update({str(info["name"]): number for number, info in MAC_ALGORITHMS.items()})
        try:
            number = aliases[normalized]
        except KeyError:
            raise GridDNP3SAError("unknown MAC algorithm name") from None
    else:
        raise GridDNP3SAError("MAC algorithm must be an integer or name")
    _mac_length(number)
    return number


def _verify_mac(
    key: bytes, algorithm: int | str, authenticated_data: bytes, mac_value: bytes, iv: bytes | None
) -> dict[str, Any]:
    key = _blob(key, name="key")
    authenticated_data = _blob(authenticated_data, name="authenticated data", allow_empty=True)
    mac_value = _blob(mac_value, name="MAC")
    number = _algorithm_id(algorithm)
    info = MAC_ALGORITHMS[number]
    expected_length = int(info["length"])
    expected: bytes
    if number == 6:
        if iv is None:
            raise GridDNP3SAError("AES-GMAC requires an explicit 12-octet IV")
        iv = _blob(iv, name="AES-GMAC IV")
        if len(iv) != 12 or len(key) not in {16, 32}:
            raise GridDNP3SAError("AES-GMAC requires a 12-octet IV and 16/32-octet key")
        try:
            from Crypto.Cipher import AES

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=12)
            cipher.update(authenticated_data)
            _, expected = cipher.encrypt_and_digest(b"")
        except Exception:
            raise GridDNP3SAError("AES-GMAC calculation failed") from None
    else:
        digest = str(info["digest"])
        expected = hmac.new(key, authenticated_data, digest).digest()[:expected_length]
    verified = len(mac_value) == expected_length and hmac.compare_digest(expected, mac_value)
    return {
        "algorithm": number,
        "algorithm_name": info["name"],
        "authenticated_length": len(authenticated_data),
        "expected_mac_length": expected_length,
        "provided_mac_length": len(mac_value),
        "verified": verified,
        "iv_source": "caller-supplied" if number == 6 else None,
    }


@_guard
def verify_mac(
    key: bytes,
    algorithm: int | str,
    authenticated_data: bytes,
    mac_value: bytes,
    *,
    iv: bytes | None = None,
) -> dict[str, Any]:
    """Verify one published DNP3 HMAC/GMAC using exact caller-supplied bytes."""
    return _verify_mac(key, algorithm, authenticated_data, mac_value, iv)


@_guard
def verify_normal_reply(
    key: bytes,
    challenge_fragment: bytes,
    reply_fragment: bytes,
    *,
    challenged_fragment: bytes | None = None,
    iv: bytes | None = None,
) -> dict[str, Any]:
    """Verify g120v2 over the full Challenge and, for reason 1, challenged ASDU."""
    challenge_raw = _blob(challenge_fragment, name="Challenge fragment")
    reply_raw = _blob(reply_fragment, name="Reply fragment")
    challenge = _parse_fragment(challenge_raw)
    reply = _parse_fragment(reply_raw)
    if [row["variation"] for row in challenge["objects"]] != [1]:
        raise GridDNP3SAError("Challenge fragment must contain only g120v1")
    if [row["variation"] for row in reply["objects"]] != [2]:
        raise GridDNP3SAError("Reply fragment must contain only g120v2")
    cobj, robj = challenge["objects"][0], reply["objects"][0]
    if cobj["sequence"] != robj["sequence"]:
        raise GridDNP3SAError("Reply CSQ does not match Challenge")
    if cobj["user"] not in {0, robj["user"]}:
        raise GridDNP3SAError("Reply user does not match Challenge")
    reason = int(cobj["reason"])
    if reason != 1:
        raise GridDNP3SAError("only the standardized critical-function reason is verifiable")
    if challenged_fragment is None:
        raise GridDNP3SAError("critical-function Challenge requires the challenged fragment")
    challenged_raw = _blob(challenged_fragment, name="challenged fragment")
    _application_header(challenged_raw)
    authenticated = challenge_raw + challenged_raw
    verification = _verify_mac(
        key,
        int(cobj["mac_algorithm"]),
        authenticated,
        bytes.fromhex(str(robj["mac_hex"])),
        iv,
    )
    return {
        "protocol": "dnp3-secure-authentication",
        "mode": "challenge-reply",
        "sequence": cobj["sequence"],
        "user": robj["user"],
        "challenge": challenge,
        "reply": reply,
        "verification": verification,
    }


@_guard
def verify_aggressive_mode(
    key: bytes,
    challenge_fragment: bytes,
    aggressive_fragment: bytes,
    *,
    iv: bytes | None = None,
) -> dict[str, Any]:
    """Verify trailing g120v9 using the exact Annex-A.45 aggressive MAC domain."""
    challenge_raw = _blob(challenge_fragment, name="Challenge fragment")
    aggressive_raw = _blob(aggressive_fragment, name="aggressive fragment")
    challenge = _parse_fragment(challenge_raw)
    aggressive = _parse_fragment(aggressive_raw)
    if [row["variation"] for row in challenge["objects"]] != [1]:
        raise GridDNP3SAError("Challenge fragment must contain only g120v1")
    if not aggressive["aggressive_mode"]:
        raise GridDNP3SAError("fragment is not g120v3 ... g120v9 aggressive mode")
    cobj = challenge["objects"][0]
    request, mac_object = aggressive["objects"]
    if cobj["user"] not in {0, request["user"]}:
        raise GridDNP3SAError("aggressive request user does not match Challenge")
    mac_offset = int(aggressive["mac_value_offset"])
    authenticated = challenge_raw + aggressive_raw[:mac_offset]
    verification = _verify_mac(
        key,
        int(cobj["mac_algorithm"]),
        authenticated,
        bytes.fromhex(str(mac_object["mac_hex"])),
        iv,
    )
    return {
        "protocol": "dnp3-secure-authentication",
        "mode": "aggressive",
        "challenge": challenge,
        "fragment": aggressive,
        "verification": verification,
    }


@_guard
def unwrap_session_key_change(
    update_key: bytes, key_status_body: bytes, key_change_body: bytes
) -> dict[str, Any]:
    """RFC-3394 unwrap g120v6 and bind it to the supplied g120v5 body."""
    update_key = _blob(update_key, name="update key")
    status_raw = _blob(key_status_body, name="SessionKeyStatus body")
    change_raw = _blob(key_change_body, name="SessionKeyChange body")
    status = _parse_sa_object(5, status_raw)
    change = _parse_sa_object(6, change_raw)
    if (status["sequence"], status["user"]) != (change["sequence"], change["user"]):
        raise GridDNP3SAError("SessionKeyChange KSQ/user does not match SessionKeyStatus")
    wrap_algorithm = int(status["key_wrap_algorithm"])
    required_key_length = {1: 16, 2: 32}.get(wrap_algorithm)
    if required_key_length is None or len(update_key) != required_key_length:
        raise GridDNP3SAError("update-key length does not match negotiated key-wrap algorithm")
    wrapped = bytes.fromhex(str(change["wrapped_key_data_hex"]))
    try:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
        from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

        try:
            plaintext = aes_key_unwrap(update_key, wrapped)
        except InvalidUnwrap:
            raise GridDNP3SAError("RFC 3394 integrity check failed") from None
    except GridDNP3SAError:
        raise
    except Exception:
        raise GridDNP3SAError("RFC 3394 unwrap is unavailable") from None
    if len(plaintext) < 2 or len(plaintext) % 8:
        raise GridDNP3SAError("unwrapped session-key plaintext is not block aligned")
    key_length = int.from_bytes(plaintext[:2], "little")
    if key_length not in {16, 32}:
        raise GridDNP3SAError("unwrapped session-key length is unsupported")
    at = 2
    _need(plaintext, at, key_length * 2, "two session keys")
    control_key = plaintext[at : at + key_length]
    at += key_length
    monitoring_key = plaintext[at : at + key_length]
    at += key_length
    status_prefix = bytes.fromhex(str(status["authenticated_prefix_hex"]))
    _need(plaintext, at, len(status_prefix), "bound SessionKeyStatus body")
    if not hmac.compare_digest(plaintext[at : at + len(status_prefix)], status_prefix):
        raise GridDNP3SAError("unwrapped data is not bound to the supplied SessionKeyStatus")
    at += len(status_prefix)
    padding = plaintext[at:]
    if len(padding) > 7:
        raise GridDNP3SAError("unwrapped key-wrap padding exceeds seven octets")
    return {
        "protocol": "dnp3-secure-authentication",
        "mode": "session-key-change",
        "sequence": status["sequence"],
        "user": status["user"],
        "key_wrap_algorithm": wrap_algorithm,
        "key_wrap_algorithm_name": status["key_wrap_algorithm_name"],
        "session_key_length": key_length,
        "control_direction_key_hex": control_key.hex(),
        "monitoring_direction_key_hex": monitoring_key.hex(),
        "padding_hex": padding.hex(),
        "status_binding_verified": True,
    }


TASE_RESERVED_NAMES = {
    "Supported_Features",
    "Bilateral_Table_ID",
    "TASE.2_Version",
    "Next_DSTransfer_Set",
    "Transfer_Set_Name",
    "DSConditions_Detected",
    "Transfer_Set_Time_Stamp",
    "Transfer_Report_ACK",
    "Transfer_Report_NACK",
}


def _walk(value: Any, path: str = "$") -> Any:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")
    else:
        yield path, value


def _analyze_iccp(data: bytes, layer: str) -> dict[str, Any]:
    if layer not in {"auto", "mms", "acse", "presentation"}:
        raise GridDNP3SAError("ICCP layer must be auto, mms, acse, or presentation")
    try:
        import ot_mms_services as mms

        decoded = mms.analyze(data, layer)
    except Exception as exc:
        raise GridDNP3SAError(f"underlying MMS/ACSE parser rejected input: {exc}") from None
    strings: list[dict[str, str]] = []
    object_names: list[dict[str, Any]] = []
    mms_pdus: list[dict[str, Any]] = []
    for path, item in _walk(decoded):
        if isinstance(item, str):
            strings.append({"path": path, "value": item})
        elif isinstance(item, dict):
            if item.get("protocol") == "mms":
                mms_pdus.append(item)
            if item.get("scope") in {"vmd", "domain", "aa"}:
                record = {"path": path, **item}
                if record not in object_names:
                    object_names.append(record)
    reserved = sorted(
        {
            row["value"]
            for row in strings
            if row["value"] in TASE_RESERVED_NAMES
        }
    )
    transfer_names = sorted(
        {
            row["value"]
            for row in strings
            if "Transfer_Set" in row["value"] or row["value"].startswith("DSConditions_")
        }
    )
    domains = sorted(
        {
            str(row["domain_id"])
            for row in object_names
            if row.get("scope") == "domain" and "domain_id" in row
        }
    )
    findings: list[dict[str, Any]] = []
    services: list[str] = []
    for pdu in mms_pdus:
        service = pdu.get("service")
        if isinstance(service, dict) and isinstance(service.get("name"), str):
            name = str(service["name"])
            services.append(name)
            if name == "write":
                findings.append(
                    {
                        "id": "iccp-mms-write",
                        "severity": "high",
                        "detail": "MMS Write can map to a TASE.2 Set/control or transfer-set change",
                    }
                )
            elif name == "information_report":
                findings.append(
                    {
                        "id": "iccp-transfer-report-candidate",
                        "severity": "info",
                        "detail": "MMS InformationReport can carry a TASE.2 transfer report",
                    }
                )
    if reserved:
        findings.append(
            {
                "id": "tase2-reserved-object",
                "severity": "info",
                "detail": "TASE.2 reserved object name(s) are present",
                "names": reserved,
            }
        )
    strength = "strong" if reserved else "possible-mms-only" if object_names else "none"
    return {
        "protocol": "iccp-tase2-evidence",
        "decoded": decoded,
        "classification": {
            "strength": strength,
            "reserved_names": reserved,
            "transfer_set_names": transfer_names,
            "domains": domains,
            "object_names": object_names,
            "mms_services": sorted(set(services)),
        },
        "findings": findings,
        "limitations": [
            "MMS syntax alone does not prove that an association negotiated TASE.2",
            "an isolated PDU cannot establish Bilateral Table authorization or delivery",
            "TLS-protected ICCP requires caller-supplied decrypted application bytes",
        ],
    }


@_guard
def analyze_iccp(data: bytes, *, layer: str = "auto") -> dict[str, Any]:
    """Classify TASE.2 artifacts atop the repository's strict MMS/ACSE decoder."""
    return _analyze_iccp(_blob(data, name="ICCP/MMS input"), layer)


@_guard
def analyze_dnp3_security_layer(
    data: bytes, *, identified_by_capture_metadata: bool = False
) -> dict[str, Any]:
    """Fingerprint explicitly identified DNP3-SL/SAv6 bytes without guessing grammar."""
    raw = _blob(data, name="DNP3-SL bytes")
    if not isinstance(identified_by_capture_metadata, bool) or not identified_by_capture_metadata:
        raise GridDNP3SAError(
            "DNP3-SL cannot be identified safely from opaque bytes without capture metadata"
        )
    return {
        "protocol": "dnp3-security-layer",
        "former_name": "Secure Authentication v6 (SAv6)",
        "parsed": False,
        "length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "reason": (
            "the public DNP-UG material defines the architecture but not a stable, "
            "authoritative DNP-specific octet grammar"
        ),
        "known_properties": [
            "separate layer between DNP application and transport",
            "authenticates every application message",
            "supports HMAC and AEAD/encryption",
            "coexists with SAv5 Group-120 authentication",
        ],
    }


def _read(path: str) -> bytes:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except OSError as exc:
        raise GridDNP3SAError(f"cannot read {path}: {exc}") from None
    return _blob(data, name=path)


def _hex_key(text: str | None, what: str) -> bytes:
    if text is None:
        raise GridDNP3SAError(f"{what} is required")
    if len(text) > MAX_INPUT * 2:
        raise GridDNP3SAError(f"{what} exceeds cap")
    try:
        value = bytes.fromhex(text)
    except ValueError:
        raise GridDNP3SAError(f"{what} is not hexadecimal") from None
    return _blob(value, name=what)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sa = subparsers.add_parser("sa", help="parse one complete DNP application fragment")
    sa.add_argument("input")
    objects = subparsers.add_parser("objects", help="parse a bare Group-120 object stream")
    objects.add_argument("input")
    iccp = subparsers.add_parser("iccp", help="classify TASE.2 evidence in supplied MMS bytes")
    iccp.add_argument("input")
    iccp.add_argument("--layer", choices=("auto", "mms", "acse", "presentation"), default="auto")
    sav6 = subparsers.add_parser("sav6", help="fingerprint metadata-identified DNP3-SL bytes")
    sav6.add_argument("input")
    sav6.add_argument("--identified-by-metadata", action="store_true")
    reply = subparsers.add_parser("verify-reply", help="verify a supplied Challenge/Reply exchange")
    reply.add_argument("reply")
    reply.add_argument("--challenge", required=True)
    reply.add_argument("--challenged", required=True)
    reply.add_argument("--key-hex", required=True)
    reply.add_argument("--iv-hex")
    aggressive = subparsers.add_parser("verify-aggressive", help="verify a supplied aggressive fragment")
    aggressive.add_argument("input")
    aggressive.add_argument("--challenge", required=True)
    aggressive.add_argument("--key-hex", required=True)
    aggressive.add_argument("--iv-hex")
    unwrap = subparsers.add_parser("unwrap", help="unwrap supplied g120v6 against g120v5")
    unwrap.add_argument("key_change_body")
    unwrap.add_argument("--status-body", required=True)
    unwrap.add_argument("--update-key-hex", required=True)

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.command == "sa":
            result = parse_dnp3_sa_fragment(_read(args.input))
        elif args.command == "objects":
            result = parse_sa_object_stream(_read(args.input))
        elif args.command == "iccp":
            result = analyze_iccp(_read(args.input), layer=args.layer)
        elif args.command == "sav6":
            result = analyze_dnp3_security_layer(
                _read(args.input), identified_by_capture_metadata=args.identified_by_metadata
            )
        elif args.command == "verify-reply":
            result = verify_normal_reply(
                _hex_key(args.key_hex, "session key"),
                _read(args.challenge),
                _read(args.reply),
                challenged_fragment=_read(args.challenged),
                iv=_hex_key(args.iv_hex, "AES-GMAC IV") if args.iv_hex else None,
            )
        elif args.command == "verify-aggressive":
            result = verify_aggressive_mode(
                _hex_key(args.key_hex, "session key"),
                _read(args.challenge),
                _read(args.input),
                iv=_hex_key(args.iv_hex, "AES-GMAC IV") if args.iv_hex else None,
            )
        else:
            result = unwrap_session_key_change(
                _hex_key(args.update_key_hex, "update key"),
                _read(args.status_body),
                _read(args.key_change_body),
            )
        print(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
                default=lambda value: value.hex() if isinstance(value, bytes) else str(value),
            )
        )
        return 0
    except (GridDNP3SAError, OSError) as exc:
        print(f"sec_gridsec_dnp3sa: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
