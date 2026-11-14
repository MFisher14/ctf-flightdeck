#!/usr/bin/env python3
"""Strict offline decoder for saved WebAuthn registration/assertion artifacts.

The analyzer accepts a JSON-serialized ``PublicKeyCredential`` (or an already
decoded JSON-style mapping), parses the exact client-data bytes and the binary
authenticator structures, and correlates them with caller-supplied ceremony
state.  It never contacts an origin, invokes an authenticator, or executes or
cryptographically trusts untrusted input.

Only the deterministic CBOR subset used by WebAuthn/CTAP structures is
accepted.  Indefinite values, tags, floating point values, duplicate map keys,
non-minimal integer encodings, and trailing bytes are rejected fail closed.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit


MAX_JSON_BYTES = 2_000_000
MAX_BINARY_BYTES = 1_000_000
MAX_CLIENT_DATA_BYTES = 131_072
MAX_SIGNATURE_BYTES = 16_384
MAX_CREDENTIAL_ID_BYTES = 1023
MAX_USER_HANDLE_BYTES = 64
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000
MAX_CBOR_DEPTH = 24
MAX_CBOR_NODES = 20_000
MAX_CBOR_ITEMS = 1024
MAX_FINDINGS = 256
MAX_TEXT_BYTES = 131_072

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*\Z")


class WebauthnArtifactError(ValueError):
    """The saved artifact is malformed, ambiguous, unsupported, or over cap."""


@dataclass(frozen=True)
class WebauthnFinding:
    code: str
    severity: str
    evidence: str
    consequence: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class WebauthnReport:
    ceremony: str
    findings: tuple[WebauthnFinding, ...]
    metadata: dict[str, object]
    offline: bool = True
    cryptographically_verified: bool = False
    network_requests: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "ceremony": self.ceremony,
            "findings": [row.as_dict() for row in self.findings],
            "metadata": self.metadata,
            "offline": self.offline,
            "cryptographically_verified": self.cryptographically_verified,
            "network_requests": self.network_requests,
        }


class _CborReader:
    """Small deterministic CBOR reader with duplicate and boundary checks."""

    def __init__(self, data: bytes, *, offset: int = 0, label: str = "CBOR") -> None:
        if not isinstance(data, bytes) or len(data) > MAX_BINARY_BYTES:
            raise WebauthnArtifactError(f"{label} is not bounded bytes")
        if not isinstance(offset, int) or not 0 <= offset <= len(data):
            raise WebauthnArtifactError(f"{label} offset is invalid")
        self.data = data
        self.offset = offset
        self.label = label
        self.nodes = 0

    def _take(self, length: int) -> bytes:
        if not isinstance(length, int) or length < 0 or length > MAX_BINARY_BYTES:
            raise WebauthnArtifactError(f"{self.label} length is invalid or over cap")
        end = self.offset + length
        if end > len(self.data):
            raise WebauthnArtifactError(f"{self.label} is truncated")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            if additional == 31:
                raise WebauthnArtifactError(f"{self.label} uses an indefinite-length value")
            raise WebauthnArtifactError(f"{self.label} has a reserved additional-info value")
        value = int.from_bytes(self._take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 4_294_967_296}[width]
        if value < minimum:
            raise WebauthnArtifactError(f"{self.label} contains a non-minimal integer/length")
        return value

    def read(self, depth: int = 0) -> object:
        if depth > MAX_CBOR_DEPTH:
            raise WebauthnArtifactError(f"{self.label} nesting exceeds {MAX_CBOR_DEPTH}")
        self.nodes += 1
        if self.nodes > MAX_CBOR_NODES:
            raise WebauthnArtifactError(f"{self.label} node count exceeds {MAX_CBOR_NODES}")
        if self.offset >= len(self.data):
            raise WebauthnArtifactError(f"{self.label} is truncated")
        initial = self._take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise WebauthnArtifactError(f"{self.label} contains unsupported simple/float data")
        argument = self._argument(additional)
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            return self._take(argument)
        if major == 3:
            try:
                return self._take(argument).decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise WebauthnArtifactError(f"{self.label} contains invalid UTF-8 text") from exc
        if major == 4:
            if argument > MAX_CBOR_ITEMS:
                raise WebauthnArtifactError(f"{self.label} array exceeds {MAX_CBOR_ITEMS} items")
            return [self.read(depth + 1) for _ in range(argument)]
        if major == 5:
            if argument > MAX_CBOR_ITEMS:
                raise WebauthnArtifactError(f"{self.label} map exceeds {MAX_CBOR_ITEMS} entries")
            result: dict[object, object] = {}
            for _ in range(argument):
                key = self.read(depth + 1)
                if not isinstance(key, (int, str, bytes)) or isinstance(key, bool):
                    raise WebauthnArtifactError(f"{self.label} has an unsupported map-key type")
                if key in result:
                    raise WebauthnArtifactError(f"{self.label} contains a duplicate map key")
                result[key] = self.read(depth + 1)
            return result
        if major == 6:
            raise WebauthnArtifactError(f"{self.label} contains an unsupported semantic tag")
        raise WebauthnArtifactError(f"{self.label} has an unsupported major type")


def _decode_cbor(data: bytes, *, label: str, offset: int = 0,
                 require_end: bool = True) -> tuple[object, int]:
    reader = _CborReader(data, offset=offset, label=label)
    value = reader.read()
    if require_end and reader.offset != len(data):
        raise WebauthnArtifactError(f"{label} contains trailing bytes")
    return value, reader.offset


def _bounded_text(value: object, *, label: str, limit: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise WebauthnArtifactError(f"{label} must be text")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError as exc:
        raise WebauthnArtifactError(f"{label} is not valid Unicode") from exc
    if size > limit or "\x00" in value:
        raise WebauthnArtifactError(f"{label} is over cap or contains NUL")
    return value


def _validate_json_tree(root: object, *, label: str) -> object:
    stack: list[tuple[object, int]] = [(root, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise WebauthnArtifactError(f"{label} node count exceeds {MAX_JSON_NODES}")
        if depth > MAX_JSON_DEPTH:
            raise WebauthnArtifactError(f"{label} nesting exceeds {MAX_JSON_DEPTH}")
        if isinstance(node, Mapping):
            if len(node) > MAX_CBOR_ITEMS:
                raise WebauthnArtifactError(f"{label} object is over cap")
            for key, value in node.items():
                if not isinstance(key, str):
                    raise WebauthnArtifactError(f"{label} object keys must be text")
                _bounded_text(key, label=f"{label} key", limit=4096)
                stack.append((value, depth + 1))
        elif isinstance(node, (list, tuple)):
            if len(node) > MAX_CBOR_ITEMS:
                raise WebauthnArtifactError(f"{label} array is over cap")
            stack.extend((value, depth + 1) for value in node)
        elif isinstance(node, str):
            _bounded_text(node, label=label)
        elif node is None or isinstance(node, (bool, int, float)):
            if isinstance(node, float) and (node != node or node in (float("inf"), float("-inf"))):
                raise WebauthnArtifactError(f"{label} contains a non-finite number")
        else:
            raise WebauthnArtifactError(f"{label} contains a non-JSON value")
    return root


def _json_object(value: object, *, label: str, byte_limit: int = MAX_JSON_BYTES) -> dict[str, object]:
    if isinstance(value, Mapping):
        parsed: object = dict(value)
    elif isinstance(value, (str, bytes, bytearray, memoryview)):
        if isinstance(value, str):
            try:
                raw = value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise WebauthnArtifactError(f"{label} is not valid Unicode") from exc
        else:
            raw = bytes(value)
        if len(raw) > byte_limit:
            raise WebauthnArtifactError(f"{label} exceeds {byte_limit} bytes")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise WebauthnArtifactError(f"{label} is not UTF-8") from exc

        def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise WebauthnArtifactError(f"{label} contains duplicate key {key!r}")
                result[key] = item
            return result

        def reject_constant(name: str) -> object:
            raise WebauthnArtifactError(f"{label} contains non-standard number {name}")

        try:
            parsed = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant)
        except WebauthnArtifactError:
            raise
        except (ValueError, OverflowError, RecursionError) as exc:
            raise WebauthnArtifactError(f"{label} is invalid JSON") from exc
    else:
        raise WebauthnArtifactError(f"{label} must be JSON text/bytes or a mapping")
    _validate_json_tree(parsed, label=label)
    if not isinstance(parsed, dict):
        raise WebauthnArtifactError(f"{label} must be a JSON object")
    return parsed


def _b64url(value: object, *, label: str, limit: int = MAX_BINARY_BYTES,
            allow_empty: bool = False) -> bytes:
    text = _bounded_text(value, label=label, limit=((limit + 2) // 3) * 4 + 4)
    if "=" in text or not _B64URL_RE.fullmatch(text):
        raise WebauthnArtifactError(f"{label} must be unpadded base64url")
    if not text and not allow_empty:
        raise WebauthnArtifactError(f"{label} must not be empty")
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WebauthnArtifactError(f"{label} is invalid base64url") from exc
    if len(decoded) > limit:
        raise WebauthnArtifactError(f"{label} decodes beyond {limit} bytes")
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != text:
        raise WebauthnArtifactError(f"{label} is not canonical base64url")
    return decoded


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _origin_status(value: str) -> tuple[bool, str]:
    """Validate a WebAuthn serialized web origin without resolving anything."""

    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False, "the authority or port is malformed"
    if (
        not parsed.scheme
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return False, "serialized origins contain only scheme, host, and optional port"
    scheme = parsed.scheme.casefold()
    if scheme == "https":
        return True, "HTTPS origin"
    if scheme != "http":
        return False, "WebAuthn web origins require HTTPS or a trustworthy HTTP loopback origin"
    host = parsed.hostname.rstrip(".").casefold()
    if host == "localhost" or host.endswith(".localhost"):
        return True, "potentially trustworthy localhost HTTP origin"
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True, "potentially trustworthy loopback HTTP origin"
    except ValueError:
        pass
    return False, "non-loopback HTTP is not a potentially trustworthy WebAuthn origin"


def _object_member(obj: Mapping[str, object], name: str, *, required: bool = True) -> object | None:
    if name not in obj:
        if required:
            raise WebauthnArtifactError(f"credential is missing {name!r}")
        return None
    return obj[name]


def _map_member(obj: Mapping[object, object], key: object, expected: type,
                *, label: str, required: bool = True) -> object | None:
    if key not in obj:
        if required:
            raise WebauthnArtifactError(f"{label} is missing {key!r}")
        return None
    value = obj[key]
    if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
        raise WebauthnArtifactError(f"{label} member {key!r} has the wrong type")
    return value


def _key_name(value: object) -> str:
    if isinstance(value, bytes):
        return "h'" + value[:24].hex() + ("..." if len(value) > 24 else "") + "'"
    return str(value)[:128]


def _cose_metadata(cose: object, findings: list[WebauthnFinding]) -> dict[str, object]:
    if not isinstance(cose, dict):
        raise WebauthnArtifactError("credentialPublicKey must be a CBOR map")
    kty = _map_member(cose, 1, int, label="COSE key")
    alg = _map_member(cose, 3, int, label="COSE key")
    names = {1: "OKP", 2: "EC2", 3: "RSA", 4: "symmetric"}
    metadata: dict[str, object] = {
        "kty": kty,
        "kty_name": names.get(kty, "unknown"),
        "alg": alg,
        "labels": sorted(str(key) for key in cose),
    }
    expected_kty = {
        -7: 2, -35: 2, -36: 2, -47: 2,
        -8: 1,
        -257: 3, -258: 3, -259: 3, -37: 3, -38: 3, -39: 3,
    }.get(alg)
    if expected_kty is None:
        _add_finding(
            findings, "unsupported_cose_alg", "medium",
            f"COSE algorithm {alg} is outside this analyzer's WebAuthn allowlist",
            "Verify credentials only with an explicitly configured and implemented COSE algorithm.",
        )
    elif kty != expected_kty:
        _add_finding(
            findings, "cose_alg_kty_mismatch", "high",
            f"COSE alg {alg} requires kty {expected_kty}, observed {kty}",
            "A verifier that selects an incompatible key/algorithm family may be vulnerable to confusion.",
        )
    if kty == 2:
        curve = _map_member(cose, -1, int, label="EC2 key")
        x = _map_member(cose, -2, bytes, label="EC2 key")
        y = _map_member(cose, -3, bytes, label="EC2 key")
        expected = {1: 32, 2: 48, 3: 66, 8: 32}.get(curve)
        metadata.update({"curve": curve, "x_bytes": len(x), "y_bytes": len(y)})
        if expected is None or len(x) != expected or len(y) != expected:
            _add_finding(findings, "cose_ec_coordinate_length", "high",
                         f"EC2 curve {curve} has coordinate lengths {len(x)}/{len(y)}",
                         "Malformed or ambiguous EC public keys must be rejected before verification.")
        if -4 in cose:
            _add_finding(findings, "cose_private_key_material", "critical", "EC2 key contains label -4 (d)",
                         "A registration artifact must contain only the credential public key.")
    elif kty == 1:
        curve = _map_member(cose, -1, int, label="OKP key")
        x = _map_member(cose, -2, bytes, label="OKP key")
        expected = {4: 32, 5: 56, 6: 32, 7: 57}.get(curve)
        metadata.update({"curve": curve, "x_bytes": len(x)})
        if expected is None or len(x) != expected:
            _add_finding(findings, "cose_okp_key_length", "high",
                         f"OKP curve {curve} has a {len(x)}-byte public key",
                         "Malformed or ambiguous OKP keys must be rejected before verification.")
        if -4 in cose:
            _add_finding(findings, "cose_private_key_material", "critical", "OKP key contains label -4 (d)",
                         "A registration artifact must contain only the credential public key.")
    elif kty == 3:
        modulus = _map_member(cose, -1, bytes, label="RSA key")
        exponent = _map_member(cose, -2, bytes, label="RSA key")
        bits = int.from_bytes(modulus, "big").bit_length()
        exp = int.from_bytes(exponent, "big")
        metadata.update({"modulus_bits": bits, "exponent": exp})
        if bits < 2048 or exp < 3 or exp % 2 == 0:
            _add_finding(findings, "cose_rsa_parameters", "high",
                         f"RSA key has {bits} bits and exponent {exp}",
                         "Use a valid RSA key of at least 2048 bits with an acceptable exponent.")
        private = sorted(label for label in range(-9, -2) if label in cose)
        if private:
            _add_finding(findings, "cose_private_key_material", "critical",
                         f"RSA key contains private labels {private}",
                         "A registration artifact must contain only the credential public key.")
    elif kty == 4:
        _map_member(cose, -1, bytes, label="symmetric key")
        _add_finding(findings, "cose_symmetric_credential_key", "critical",
                     "credentialPublicKey contains a symmetric secret",
                     "WebAuthn credentials require an asymmetric public key bound to the authenticator.")
    else:
        _add_finding(findings, "cose_unknown_kty", "high", f"unsupported COSE kty {kty}",
                     "Use a WebAuthn-supported, explicitly allowlisted key type and algorithm.")
    return metadata


def _attestation_metadata(fmt: str, statement: object,
                          findings: list[WebauthnFinding]) -> dict[str, object]:
    if not isinstance(statement, dict):
        raise WebauthnArtifactError("attStmt must be a CBOR map")
    alg = statement.get("alg")
    if alg is not None and (not isinstance(alg, int) or isinstance(alg, bool)):
        raise WebauthnArtifactError("attStmt alg must be an integer")
    sig = statement.get("sig")
    if sig is not None and not isinstance(sig, bytes):
        raise WebauthnArtifactError("attStmt sig must be bytes")
    certificates = statement.get("x5c")
    cert_lengths: list[int] = []
    if certificates is not None:
        if (not isinstance(certificates, list) or len(certificates) > 16
                or any(not isinstance(item, bytes) or not item for item in certificates)):
            raise WebauthnArtifactError("attStmt x5c must be a bounded array of non-empty certificates")
        cert_lengths = [len(item) for item in certificates]
    if fmt == "none" and statement:
        _add_finding(findings, "attestation_none_nonempty", "high", "fmt=none has a non-empty attStmt",
                     "The none attestation format requires an empty attestation statement.")
    if fmt == "packed" and (not isinstance(alg, int) or not isinstance(sig, bytes) or not sig):
        _add_finding(findings, "attestation_packed_incomplete", "high",
                     "packed attestation lacks a non-empty sig or integer alg",
                     "Reject an incomplete packed attestation statement.")
    if fmt not in {"none", "packed"}:
        _add_finding(findings, "attestation_format_unvalidated", "info",
                     f"attestation format {fmt!r} received structural inventory only",
                     "Apply the format-specific WebAuthn verification procedure before trusting attestation.")
    return {
        "format": fmt,
        "alg": alg,
        "signature_bytes": len(sig) if isinstance(sig, bytes) else 0,
        "certificate_count": len(cert_lengths),
        "certificate_lengths": cert_lengths,
        "statement_keys": sorted(_key_name(key) for key in statement),
    }


def _authenticator_data(data: bytes, *, ceremony: str,
                        findings: list[WebauthnFinding]) -> dict[str, object]:
    if not isinstance(data, bytes) or len(data) > MAX_BINARY_BYTES:
        raise WebauthnArtifactError("authenticatorData must be bounded bytes")
    if len(data) < 37:
        raise WebauthnArtifactError("authenticatorData is shorter than 37 bytes")
    rp_hash = data[:32]
    flags = data[32]
    sign_count = int.from_bytes(data[33:37], "big")
    offset = 37
    names = tuple(name for mask, name in (
        (0x01, "UP"), (0x04, "UV"), (0x08, "BE"), (0x10, "BS"),
        (0x40, "AT"), (0x80, "ED"),
    ) if flags & mask)
    result: dict[str, object] = {
        "bytes": len(data), "rp_id_hash": rp_hash.hex(), "flags": flags,
        "flag_names": list(names), "sign_count": sign_count,
    }
    if flags & 0x02 or flags & 0x20:
        _add_finding(findings, "authenticator_reserved_flags", "medium",
                     f"authenticatorData sets reserved flag bits 0x{flags & 0x22:02x}",
                     "Reserved flag bits should not be used without an applicable specification extension.")
    if flags & 0x10 and not flags & 0x08:
        _add_finding(findings, "authenticator_backup_flags", "high", "BS is set while BE is clear",
                     "Reject the internally inconsistent backup-state flags.")
    if ceremony == "registration" and not flags & 0x40:
        _add_finding(findings, "registration_missing_attested_data", "high", "AT flag is clear",
                     "A registration response must convey the newly created credential public key.")
    if ceremony == "assertion" and flags & 0x40:
        _add_finding(findings, "assertion_has_attested_data", "medium", "AT flag is set on an assertion",
                     "Use ceremony-specific parsing and reject unexpected attested credential data by policy.")
    if flags & 0x40:
        if len(data) - offset < 18:
            raise WebauthnArtifactError("attested credential data is truncated")
        aaguid = data[offset:offset + 16]
        credential_length = int.from_bytes(data[offset + 16:offset + 18], "big")
        offset += 18
        if credential_length > MAX_CREDENTIAL_ID_BYTES:
            raise WebauthnArtifactError(
                f"credential ID length exceeds {MAX_CREDENTIAL_ID_BYTES} bytes"
            )
        if len(data) - offset < credential_length:
            raise WebauthnArtifactError("credential ID is truncated")
        credential_id = data[offset:offset + credential_length]
        if not credential_id:
            raise WebauthnArtifactError("credential ID is empty")
        offset += credential_length
        cose, offset = _decode_cbor(data, label="credentialPublicKey", offset=offset, require_end=False)
        result.update({
            "aaguid": aaguid.hex(),
            "credential_id": _b64encode(credential_id),
            "credential_id_bytes": len(credential_id),
            "cose_key": _cose_metadata(cose, findings),
        })
    if flags & 0x80:
        extensions, offset = _decode_cbor(data, label="authenticator extensions", offset=offset,
                                          require_end=False)
        if not isinstance(extensions, dict):
            raise WebauthnArtifactError("authenticator extensions must be a CBOR map")
        result["extensions"] = sorted(_key_name(key) for key in extensions)
    if offset != len(data):
        raise WebauthnArtifactError("authenticatorData contains trailing bytes or data without AT/ED flags")
    return result


def _add_finding(rows: list[WebauthnFinding], code: str, severity: str,
                 evidence: str, consequence: str) -> None:
    if len(rows) >= MAX_FINDINGS:
        raise WebauthnArtifactError(f"finding count exceeds {MAX_FINDINGS}")
    rows.append(WebauthnFinding(code, severity, evidence[:512], consequence[:512]))


def _normalize_credential_id(value: object, *, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        result = bytes(value)
        if not result or len(result) > MAX_CREDENTIAL_ID_BYTES:
            raise WebauthnArtifactError(f"{label} is empty or over cap")
        return result
    return _b64url(value, label=label, limit=MAX_CREDENTIAL_ID_BYTES)


def _registered_map(value: object) -> dict[bytes, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_CBOR_ITEMS:
        raise WebauthnArtifactError("registered_credentials must be a bounded mapping")
    result: dict[bytes, str] = {}
    for raw_id, owner in value.items():
        credential_id = _normalize_credential_id(raw_id, label="registered credential ID")
        owner_text = _bounded_text(owner, label="registered credential owner", limit=4096)
        if credential_id in result:
            raise WebauthnArtifactError("registered_credentials contains duplicate normalized IDs")
        result[credential_id] = owner_text
    return result


def _expected_challenge_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if not raw or len(raw) > MAX_CLIENT_DATA_BYTES:
            raise WebauthnArtifactError("expected_challenge is empty or over cap")
        return _b64encode(raw)
    text = _bounded_text(value, label="expected_challenge")
    _b64url(text, label="expected_challenge", limit=MAX_CLIENT_DATA_BYTES)
    return text


def _analyze(
    credential: object,
    *,
    ceremony: str | None,
    expected_challenge: object,
    expected_origin: str | None,
    expected_rp_id: str | None,
    require_up: bool,
    require_uv: bool,
    expected_credential_id: object,
    registered_credentials: object,
    expected_owner: str | None,
) -> WebauthnReport:
    root = _json_object(credential, label="PublicKeyCredential")
    response = _object_member(root, "response")
    if not isinstance(response, dict):
        raise WebauthnArtifactError("credential response must be a JSON object")
    has_registration = "attestationObject" in response
    has_assertion = "authenticatorData" in response or "signature" in response
    if ceremony is None:
        if has_registration == has_assertion:
            raise WebauthnArtifactError("cannot unambiguously infer registration versus assertion")
        ceremony = "registration" if has_registration else "assertion"
    if ceremony not in {"registration", "assertion"}:
        raise WebauthnArtifactError("ceremony must be registration or assertion")
    if ceremony == "registration" and not has_registration:
        raise WebauthnArtifactError("registration response lacks attestationObject")
    if ceremony == "assertion" and not ("authenticatorData" in response and "signature" in response):
        raise WebauthnArtifactError("assertion response lacks authenticatorData or signature")
    if not isinstance(require_up, bool) or not isinstance(require_uv, bool):
        raise WebauthnArtifactError("require_up and require_uv must be booleans")

    credential_type = _bounded_text(_object_member(root, "type"), label="credential type", limit=128)
    credential_id_text = _bounded_text(_object_member(root, "id"), label="credential id")
    id_bytes = _b64url(credential_id_text, label="credential id", limit=MAX_CREDENTIAL_ID_BYTES)
    raw_id = _b64url(_object_member(root, "rawId"), label="credential rawId",
                     limit=MAX_CREDENTIAL_ID_BYTES)
    findings: list[WebauthnFinding] = []
    if credential_type != "public-key":
        _add_finding(findings, "credential_type", "high", f"type is {credential_type!r}",
                     "Only public-key credentials belong to a WebAuthn ceremony.")
    if id_bytes != raw_id:
        _add_finding(findings, "credential_id_raw_id_mismatch", "high", "id and rawId decode differently",
                     "Reject inconsistent serialized identifiers before account lookup.")

    client_raw = _b64url(_object_member(response, "clientDataJSON"), label="clientDataJSON",
                         limit=MAX_CLIENT_DATA_BYTES)
    client = _json_object(client_raw, label="clientDataJSON", byte_limit=MAX_CLIENT_DATA_BYTES)
    client_type = _bounded_text(_object_member(client, "type"), label="clientDataJSON.type", limit=128)
    challenge = _bounded_text(_object_member(client, "challenge"), label="clientDataJSON.challenge")
    _b64url(challenge, label="clientDataJSON.challenge", limit=MAX_CLIENT_DATA_BYTES)
    origin = _bounded_text(_object_member(client, "origin"), label="clientDataJSON.origin", limit=8192)
    expected_type = "webauthn.create" if ceremony == "registration" else "webauthn.get"
    if client_type != expected_type:
        _add_finding(findings, "client_data_type", "critical",
                     f"clientDataJSON type {client_type!r}; expected {expected_type!r}",
                     "Bind the signed client data to the server-side ceremony type.")
    expected_challenge_text = _expected_challenge_text(expected_challenge)
    if expected_challenge_text is not None and challenge != expected_challenge_text:
        _add_finding(findings, "challenge_mismatch", "critical", "client challenge differs from saved state",
                     "Require the exact single-use challenge issued for this browser session.")
    if expected_origin is not None:
        expected_origin = _bounded_text(expected_origin, label="expected_origin", limit=8192)
        expected_valid, expected_reason = _origin_status(expected_origin)
        if not expected_valid:
            raise WebauthnArtifactError(f"expected_origin is not a serialized WebAuthn origin: {expected_reason}")
        if origin != expected_origin:
            _add_finding(findings, "origin_mismatch", "critical",
                         f"origin {origin!r}; expected {expected_origin!r}",
                         "Require exact origin binding, including scheme and effective port.")
    origin_valid, origin_reason = _origin_status(origin)
    if not origin_valid:
        _add_finding(findings, "origin_shape", "high", f"origin is {origin!r}: {origin_reason}",
                     "WebAuthn origins must be serialized origins rather than arbitrary URLs.")
    cross_origin = client.get("crossOrigin", False)
    if not isinstance(cross_origin, bool):
        raise WebauthnArtifactError("clientDataJSON.crossOrigin must be boolean")
    top_origin = client.get("topOrigin")
    if top_origin is not None:
        top_origin = _bounded_text(top_origin, label="clientDataJSON.topOrigin", limit=8192)
        top_valid, top_reason = _origin_status(top_origin)
        if not top_valid:
            _add_finding(findings, "top_origin_shape", "high",
                         f"topOrigin is {top_origin!r}: {top_reason}",
                         "Validate cross-origin embedding against a serialized, trustworthy top origin.")
    if cross_origin:
        if top_origin is None:
            _add_finding(findings, "top_origin_missing", "high",
                         "crossOrigin=true without topOrigin",
                         "Cross-origin client data must identify the top-level origin for RP policy checks.")
        _add_finding(findings, "cross_origin_ceremony", "medium",
                     f"crossOrigin=true; topOrigin={top_origin!r}",
                     "Accept cross-origin ceremonies only under an explicit, validated embedding policy.")

    attestation_meta: dict[str, object] | None = None
    if ceremony == "registration":
        attestation_raw = _b64url(_object_member(response, "attestationObject"),
                                  label="attestationObject", limit=MAX_BINARY_BYTES)
        attestation, _ = _decode_cbor(attestation_raw, label="attestationObject")
        if not isinstance(attestation, dict):
            raise WebauthnArtifactError("attestationObject must be a CBOR map")
        fmt = _map_member(attestation, "fmt", str, label="attestationObject")
        if len(fmt.encode("utf-8")) > 128:
            raise WebauthnArtifactError("attestation format name is over cap")
        auth_raw = _map_member(attestation, "authData", bytes, label="attestationObject")
        statement = _map_member(attestation, "attStmt", dict, label="attestationObject")
        auth_meta = _authenticator_data(auth_raw, ceremony=ceremony, findings=findings)
        attestation_meta = _attestation_metadata(fmt, statement, findings)
    else:
        auth_raw = _b64url(_object_member(response, "authenticatorData"),
                           label="authenticatorData", limit=MAX_BINARY_BYTES)
        auth_meta = _authenticator_data(auth_raw, ceremony=ceremony, findings=findings)
        signature = _b64url(_object_member(response, "signature"), label="signature",
                            limit=MAX_SIGNATURE_BYTES)
        attestation_meta = None
        auth_meta["assertion_signature_bytes"] = len(signature)
        user_handle_value = response.get("userHandle")
        if user_handle_value is not None:
            user_handle = _b64url(user_handle_value, label="userHandle", limit=MAX_USER_HANDLE_BYTES,
                                  allow_empty=True)
            auth_meta["user_handle"] = _b64encode(user_handle)
            _add_finding(findings, "user_handle_unsigned_hint", "info",
                         f"userHandle={_b64encode(user_handle)!r}",
                         "userHandle is not covered by the authenticator signature; use it only as a lookup hint and authenticate by the registered credential owner.")

    flags = int(auth_meta["flags"])
    if require_up and not flags & 0x01:
        _add_finding(findings, "user_presence_required", "critical", "UP flag is clear",
                     "The relying-party policy requires proof of user presence.")
    if require_uv and not flags & 0x04:
        _add_finding(findings, "user_verification_required", "critical", "UV flag is clear",
                     "The relying-party policy requires local user verification.")
    if expected_rp_id is not None:
        rp_id = _bounded_text(expected_rp_id, label="expected_rp_id", limit=4096)
        expected_hash = hashlib.sha256(rp_id.encode("utf-8")).hexdigest()
        if auth_meta["rp_id_hash"] != expected_hash:
            _add_finding(findings, "rp_id_hash_mismatch", "critical",
                         f"rpIdHash {auth_meta['rp_id_hash']}; expected SHA-256({rp_id!r})",
                         "Bind the authenticator signature to the configured relying-party ID.")

    if ceremony == "registration" and "credential_id" in auth_meta:
        attested_id = _b64url(auth_meta["credential_id"], label="attested credential ID",
                              limit=MAX_CREDENTIAL_ID_BYTES)
        if attested_id != raw_id:
            _add_finding(findings, "attested_credential_id_mismatch", "critical",
                         "rawId differs from the credential ID inside authenticatorData",
                         "Store the credential ID actually bound to the attested public key.")
    if expected_credential_id is not None:
        expected_id = _normalize_credential_id(expected_credential_id, label="expected_credential_id")
        if raw_id != expected_id:
            _add_finding(findings, "expected_credential_id_mismatch", "critical",
                         "credential rawId differs from the expected credential",
                         "Require the credential selected for the saved account/allowCredentials entry.")

    registry = _registered_map(registered_credentials)
    if expected_owner is not None:
        expected_owner = _bounded_text(expected_owner, label="expected_owner", limit=4096)
        if registered_credentials is None:
            raise WebauthnArtifactError("expected_owner requires registered_credentials")
    selected_owner = registry.get(raw_id) if registry else None
    if registered_credentials is not None and selected_owner is None:
        _add_finding(findings, "credential_not_registered", "critical",
                     "credential rawId is absent from the registered credential map",
                     "Authenticate only with a credential registered to an RP account.")
    if expected_owner is not None and selected_owner != expected_owner:
        _add_finding(findings, "credential_owner_mismatch", "critical",
                     f"registered owner {selected_owner!r}; expected {expected_owner!r}",
                     "A valid signature must not authenticate a different account than the credential owner.")

    metadata: dict[str, object] = {
        "credential_id": _b64encode(raw_id),
        "credential_type": credential_type,
        "client_data": {
            "type": client_type,
            "challenge": challenge,
            "origin": origin,
            "cross_origin": cross_origin,
            "top_origin": top_origin,
            "sha256": hashlib.sha256(client_raw).hexdigest(),
            "bytes": len(client_raw),
        },
        "authenticator_data": auth_meta,
        "registered_owner": selected_owner,
    }
    if attestation_meta is not None:
        metadata["attestation"] = attestation_meta
    return WebauthnReport(ceremony, tuple(findings), metadata)


def analyze_webauthn(
    credential: object,
    *,
    ceremony: str | None = None,
    expected_challenge: object = None,
    expected_origin: str | None = None,
    expected_rp_id: str | None = None,
    require_up: bool = True,
    require_uv: bool = False,
    expected_credential_id: object = None,
    registered_credentials: object = None,
    expected_owner: str | None = None,
) -> WebauthnReport:
    """Decode and correlate one saved WebAuthn credential, entirely offline.

    ``registered_credentials`` maps credential IDs (bytes or unpadded-base64url
    strings) to RP account identifiers.  The signed credential ID, not the
    assertion's unsigned ``userHandle``, is authoritative for account binding.
    """

    try:
        return _analyze(
            credential,
            ceremony=ceremony,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            expected_rp_id=expected_rp_id,
            require_up=require_up,
            require_uv=require_uv,
            expected_credential_id=expected_credential_id,
            registered_credentials=registered_credentials,
            expected_owner=expected_owner,
        )
    except WebauthnArtifactError:
        raise
    except Exception as exc:
        raise WebauthnArtifactError("WebAuthn artifact could not be parsed safely") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Strict offline WebAuthn artifact decoder")
    parser.add_argument("artifact", help="PublicKeyCredential JSON file")
    parser.add_argument("--ceremony", choices=("registration", "assertion"))
    parser.add_argument("--expected-challenge", help="expected unpadded-base64url challenge")
    parser.add_argument("--expected-origin")
    parser.add_argument("--rp-id", dest="expected_rp_id")
    parser.add_argument("--expected-credential-id", help="expected unpadded-base64url credential ID")
    parser.add_argument("--registered-credentials", help="JSON object mapping credential IDs to owners")
    parser.add_argument("--expected-owner")
    parser.add_argument("--require-uv", action="store_true")
    parser.add_argument("--allow-no-up", action="store_true")
    return parser


def _read_bounded_file(path: str, *, label: str, limit: int) -> bytes:
    try:
        item = Path(path)
        if not item.is_file() or item.stat().st_size > limit:
            raise WebauthnArtifactError(f"{label} is absent or exceeds {limit} bytes")
        with item.open("rb") as handle:
            raw = handle.read(limit + 1)
    except WebauthnArtifactError:
        raise
    except OSError as exc:
        raise WebauthnArtifactError(f"cannot read {label}") from exc
    if len(raw) > limit:
        raise WebauthnArtifactError(f"{label} exceeds {limit} bytes")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        artifact = _read_bounded_file(args.artifact, label="credential artifact", limit=MAX_JSON_BYTES)
        registry: object = None
        if args.registered_credentials:
            registry = _json_object(
                _read_bounded_file(
                    args.registered_credentials,
                    label="registered credential map",
                    limit=MAX_JSON_BYTES,
                ),
                label="registered credential map",
            )
        report = analyze_webauthn(
            artifact,
            ceremony=args.ceremony,
            expected_challenge=args.expected_challenge,
            expected_origin=args.expected_origin,
            expected_rp_id=args.expected_rp_id,
            require_up=not args.allow_no_up,
            require_uv=args.require_uv,
            expected_credential_id=args.expected_credential_id,
            registered_credentials=registry,
            expected_owner=args.expected_owner,
        )
    except WebauthnArtifactError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0


__all__ = [
    "WebauthnArtifactError", "WebauthnFinding", "WebauthnReport", "analyze_webauthn", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
