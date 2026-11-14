#!/usr/bin/env python3
"""Bounded static identity-artifact and saved-flow analysis.

Supported evidence includes compact/JSON JOSE (JWT/JWS/JWE), JWK/JWKS,
regex-only SAML wrapping indicators, and saved OAuth/OIDC authorization,
callback, token-request, and token-response artifacts.  The module performs no
signature creation or verification, key guessing, HTTP request, replay, XML
parsing, or unsafe deserialization.  Standard-library JSON is accepted only
through a bounded duplicate-preserving loader.

Mutation builders return a non-wire ``R5D_INERT_MUTATION`` plan DSL.  They do
not return a compact token, XML document, URL, form body, signature, or key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit


MAX_TOKEN_CHARS = 196_608
MAX_JSON_BYTES = 131_072
MAX_XML_BYTES = 2 * 1024 * 1024
MAX_FLOW_CHARS = 131_072
MAX_FIELDS = 256
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 16_384
MAX_KEYS = 64
MAX_FINDINGS = 512
MAX_SEGMENT_BYTES = 2 * 1024 * 1024
MAX_EXPECTED_BYTES = 8192

_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]*\Z")
_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_.:-]{3,63}\Z")

_SIGNATURE_LENGTHS: dict[str, tuple[int, ...]] = {
    "HS256": (32,), "HS384": (48,), "HS512": (64,),
    "ES256": (64,), "ES384": (96,), "ES512": (132,),
    "EdDSA": (64, 114),
}
_RSA_ALGS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
_KNOWN_JWS_ALGS = frozenset(_SIGNATURE_LENGTHS).union(_RSA_ALGS, {"none"})
_JWE_ALGS = frozenset({
    "dir", "RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW",
    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
    "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
})
_JWE_ENC: dict[str, tuple[int, int, int]] = {
    "A128GCM": (16, 12, 16),
    "A192GCM": (24, 12, 16),
    "A256GCM": (32, 12, 16),
    "A128CBC-HS256": (32, 16, 16),
    "A192CBC-HS384": (48, 16, 24),
    "A256CBC-HS512": (64, 16, 32),
}
_CURVE_LENGTHS = {"P-256": 32, "P-384": 48, "P-521": 66}
_OKP_LENGTHS = {"Ed25519": 32, "Ed448": 57, "X25519": 32, "X448": 56}


class IdentityInputError(ValueError):
    """Saved identity input is malformed, unsafe to interpret, or over cap."""


@dataclass(frozen=True)
class IdentityFinding:
    domain: str
    code: str
    severity: str
    evidence: str
    precondition: str
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IdentityReport:
    domain: str
    artifact_type: str
    findings: tuple[IdentityFinding, ...]
    duplicates: tuple[str, ...]
    metadata: dict[str, object]
    offline: bool = True
    verified: bool = False
    replayed: bool = False
    requests_sent: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "artifact_type": self.artifact_type,
            "findings": [item.as_dict() for item in self.findings],
            "duplicates": list(self.duplicates),
            "metadata": self.metadata,
            "offline": self.offline,
            "verified": self.verified,
            "replayed": self.replayed,
            "requests_sent": self.requests_sent,
        }


@dataclass(frozen=True)
class MutationSkeleton:
    domain: str
    mutation: str
    skeleton: str
    marker: str
    evidence: tuple[str, ...]
    preconditions: tuple[str, ...]
    inert: bool = True
    wire_artifact: bool = False
    signed: bool = False
    replayable: bool = False
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["evidence"] = list(self.evidence)
        row["preconditions"] = list(self.preconditions)
        return row


@dataclass(frozen=True)
class _JsonDocument:
    value: object
    duplicates: tuple[str, ...]


@dataclass(frozen=True)
class _Fields:
    pairs: tuple[tuple[str, str], ...]
    values: dict[str, tuple[str, ...]]
    duplicates: tuple[str, ...]

    def one(self, name: str) -> str | None:
        rows = self.values.get(name, ())
        return rows[0] if len(rows) == 1 else None


def _finding(
    domain: str,
    code: str,
    severity: str,
    evidence: str,
    precondition: str = "none; this is direct static evidence in the saved artifact",
) -> IdentityFinding:
    return IdentityFinding(domain, code, severity, evidence[:512], precondition[:512])


def _append(rows: list[IdentityFinding], finding: IdentityFinding) -> None:
    if len(rows) >= MAX_FINDINGS:
        raise IdentityInputError(f"finding cap exceeded ({MAX_FINDINGS})")
    rows.append(finding)


def _bounded_text(value: object, *, label: str, byte_limit: int) -> str:
    if isinstance(value, str):
        text = value
        try:
            size = len(text.encode("utf-8", "strict"))
        except UnicodeEncodeError as exc:
            raise IdentityInputError(f"{label} is not valid UTF-8 text") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        size = len(raw)
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise IdentityInputError(f"{label} is not UTF-8") from exc
    else:
        raise IdentityInputError(f"{label} must be text or bytes")
    if size > byte_limit:
        raise IdentityInputError(f"{label} exceeds {byte_limit} bytes")
    return text


def _expected_text(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IdentityInputError(f"{label} must be text or None")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError as exc:
        raise IdentityInputError(f"{label} is not valid UTF-8 text") from exc
    if size > MAX_EXPECTED_BYTES or "\x00" in value:
        raise IdentityInputError(f"{label} exceeds its bound or contains NUL")
    return value


def _validated_now(now: object) -> float | None:
    if now is None:
        return None
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(float(now)):
        raise IdentityInputError("now must be a finite numeric timestamp")
    return float(now)


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


def _safe_json(value: object, *, label: str = "JSON") -> _JsonDocument:
    text = _bounded_text(value, label=label, byte_limit=MAX_JSON_BYTES)
    duplicates: list[str] = []
    field_count = 0

    def hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal field_count
        result: dict[str, object] = {}
        for key, item in pairs:
            field_count += 1
            if field_count > MAX_FIELDS:
                raise IdentityInputError(f"{label} field cap exceeded ({MAX_FIELDS})")
            if key in result:
                duplicates.append(key)
            result[key] = item
        return result

    def reject_constant(name: str) -> object:
        raise IdentityInputError(f"{label} contains non-standard numeric constant {name}")

    try:
        parsed = json.loads(text, object_pairs_hook=hook, parse_constant=reject_constant)
    except IdentityInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise IdentityInputError(f"invalid {label}") from exc

    stack: list[tuple[object, int]] = [(parsed, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise IdentityInputError(f"{label} node cap exceeded ({MAX_JSON_NODES})")
        if depth > MAX_JSON_DEPTH:
            raise IdentityInputError(f"{label} nesting exceeds {MAX_JSON_DEPTH}")
        if isinstance(node, dict):
            stack.extend((item, depth + 1) for item in node.values() if isinstance(item, (dict, list)))
        elif isinstance(node, list):
            stack.extend((item, depth + 1) for item in node if isinstance(item, (dict, list)))
    return _JsonDocument(parsed, _ordered_unique(duplicates))


def _b64u_decode(segment: str, *, label: str, limit: int = MAX_SEGMENT_BYTES) -> bytes:
    if not isinstance(segment, str) or not _B64URL_RE.fullmatch(segment):
        raise IdentityInputError(f"{label} is not unpadded base64url")
    if len(segment) > ((limit + 2) // 3) * 4 + 4:
        raise IdentityInputError(f"{label} exceeds encoded cap")
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IdentityInputError(f"invalid {label}") from exc
    if len(raw) > limit:
        raise IdentityInputError(f"{label} exceeds {limit} decoded bytes")
    return raw


def _json_segment(segment: str, *, label: str) -> _JsonDocument:
    return _safe_json(_b64u_decode(segment, label=label, limit=MAX_JSON_BYTES), label=label)


def _duplicate_findings(domain: str, prefix: str, duplicates: tuple[str, ...]) -> list[IdentityFinding]:
    return [
        _finding(
            domain,
            "duplicate_field",
            "high",
            f"{prefix} contains duplicate field {name!r}",
            "the producer and verifier may resolve duplicate fields differently",
        )
        for name in duplicates
    ]


def _check_crit(header: dict[str, object], domain: str, rows: list[IdentityFinding]) -> None:
    crit = header.get("crit")
    if domain in ("jwt", "jws") and header.get("b64") is False and (
        not isinstance(crit, list) or "b64" not in crit
    ):
        _append(rows, _finding(
            domain, "b64_not_critical", "high", "b64=false is not declared in crit",
            "the verifier must implement RFC 7797 and treat b64 as critical",
        ))
    if crit is None:
        return
    if not isinstance(crit, list) or any(not isinstance(item, str) for item in crit):
        _append(rows, _finding(domain, "invalid_crit", "high", "crit is not a string array"))
        return
    if len(crit) != len(set(crit)):
        _append(rows, _finding(domain, "duplicate_crit", "high", "crit repeats a parameter"))
    for name in crit:
        if name not in header:
            _append(rows, _finding(domain, "missing_critical_parameter", "high", f"crit names absent header member {name!r}"))
        if name != "b64" or domain not in ("jwt", "jws"):
            _append(rows, _finding(
                domain, "unsupported_critical_parameter", "medium", f"critical parameter {name!r}",
                "the actual verifier must explicitly implement the named critical extension",
            ))


def _check_jws_signature(alg: object, signature: bytes, rows: list[IdentityFinding], domain: str) -> None:
    if not isinstance(alg, str) or not alg:
        _append(rows, _finding(domain, "missing_algorithm", "high", "alg is absent or non-string"))
        return
    if alg not in _KNOWN_JWS_ALGS:
        _append(rows, _finding(
            domain, "unknown_algorithm", "medium", f"unrecognized alg {alg!r}",
            "the verifier must support this exact case-sensitive algorithm identifier",
        ))
        return
    if alg == "none":
        _append(rows, _finding(
            domain, "unsecured_algorithm", "high", "alg is 'none'",
            "the verifier would have to accept unsecured JWTs in this trust context",
        ))
        if signature:
            _append(rows, _finding(domain, "none_with_signature", "medium", "alg none carries non-empty signature bytes"))
        return
    if not signature:
        _append(rows, _finding(domain, "missing_signature", "high", f"{alg} has an empty signature segment"))
        return
    expected = _SIGNATURE_LENGTHS.get(alg)
    if expected is not None and len(signature) not in expected:
        _append(rows, _finding(
            domain, "signature_length_mismatch", "high",
            f"{alg} signature is {len(signature)} bytes; expected one of {expected}",
            "the captured artifact must be intended for this declared algorithm",
        ))
    elif alg in _RSA_ALGS and not 256 <= len(signature) <= 1024:
        _append(rows, _finding(
            domain, "rsa_signature_length_suspicious", "medium",
            f"{alg} signature is {len(signature)} bytes",
            "the verifier key modulus length must match the signature length",
        ))


def _numeric_claim(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _check_claims(
    claims: dict[str, object],
    rows: list[IdentityFinding],
    *,
    domain: str,
    now: float | None,
    expected_issuer: str | None,
    expected_audience: str | None,
    expected_nonce: str | None,
) -> None:
    for name in ("exp", "nbf", "iat"):
        if name in claims and _numeric_claim(claims[name]) is None:
            _append(rows, _finding(domain, "invalid_numeric_date", "high", f"claim {name!r} is not a finite number"))
    if now is not None:
        exp = _numeric_claim(claims.get("exp"))
        nbf = _numeric_claim(claims.get("nbf"))
        iat = _numeric_claim(claims.get("iat"))
        if exp is not None and exp <= float(now):
            _append(rows, _finding(domain, "expired", "high", f"exp {exp:g} is not after now {float(now):g}"))
        if nbf is not None and nbf > float(now):
            _append(rows, _finding(domain, "not_yet_valid", "high", f"nbf {nbf:g} is after now {float(now):g}"))
        if iat is not None and iat > float(now) + 300:
            _append(rows, _finding(domain, "issued_in_future", "medium", f"iat {iat:g} is over 300 seconds after now"))
    if expected_issuer is not None:
        issuer = claims.get("iss")
        if issuer != expected_issuer:
            _append(rows, _finding(
                domain, "issuer_mismatch", "high", f"iss is {issuer!r}; expected {expected_issuer!r}",
                "the caller-supplied expected issuer is the exact trust anchor for this flow",
            ))
    if expected_audience is not None:
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
        if expected_audience not in audiences:
            _append(rows, _finding(
                domain, "audience_mismatch", "high", f"aud does not include {expected_audience!r}",
                "the caller-supplied client/resource identifier is the required audience",
            ))
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1 and not isinstance(claims.get("azp"), str):
        _append(rows, _finding(domain, "missing_azp", "medium", "multiple audiences are present without azp"))
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        _append(rows, _finding(
            domain, "nonce_mismatch", "high", f"nonce is {claims.get('nonce')!r}; expected saved request nonce",
            "the ID token must correspond to the same browser authorization request",
        ))


def _header_trust_findings(header: dict[str, object], rows: list[IdentityFinding], domain: str) -> None:
    for member in ("jku", "x5u"):
        if isinstance(header.get(member), str):
            _append(rows, _finding(
                domain, "remote_key_locator", "medium", f"header contains {member}={header[member]!r}",
                "the verifier would have to dereference or trust an attacker-influenced key location",
            ))
    if isinstance(header.get("jwk"), dict):
        _append(rows, _finding(
            domain, "embedded_jwk", "medium", "header embeds a JWK",
            "the verifier would have to trust header-supplied key material rather than configured keys",
        ))
    kid = header.get("kid")
    if isinstance(kid, str) and ("/" in kid or "\\" in kid or "://" in kid or ".." in kid):
        _append(rows, _finding(
            domain, "structured_kid", "medium", f"kid contains path/URL syntax: {kid!r}",
            "the verifier would have to interpolate kid into a path, URL, query, or command-like lookup",
        ))


def _analyze_compact_jwt(
    token: str,
    *,
    now: float | None,
    expected_issuer: str | None,
    expected_audience: str | None,
    expected_nonce: str | None,
) -> IdentityReport:
    parts = token.split(".")
    if len(parts) != 3:
        raise IdentityInputError("compact JWT/JWS must contain three segments")
    header_doc = _json_segment(parts[0], label="JWT protected header")
    if not isinstance(header_doc.value, dict):
        raise IdentityInputError("JWT protected header must be an object")
    header = header_doc.value
    if header.get("b64") is False and "b64" in (header.get("crit") or []):
        payload_doc = _safe_json(parts[1], label="unencoded JWT payload")
    else:
        payload_doc = _json_segment(parts[1], label="JWT payload")
    if not isinstance(payload_doc.value, dict):
        raise IdentityInputError("JWT payload must be an object")
    signature = _b64u_decode(parts[2], label="JWT signature", limit=2048)
    findings = _duplicate_findings("jwt", "protected header", header_doc.duplicates)
    findings.extend(_duplicate_findings("jwt", "payload", payload_doc.duplicates))
    _check_crit(header, "jwt", findings)
    _check_jws_signature(header.get("alg"), signature, findings, "jwt")
    _header_trust_findings(header, findings, "jwt")
    if header.get("b64") is False:
        _append(findings, _finding(
            "jwt", "unencoded_payload", "medium", "protected header declares b64=false",
            "the verifier must implement RFC 7797 and bind the exact external/inline payload bytes",
        ))
    _check_claims(
        payload_doc.value,
        findings,
        domain="jwt",
        now=now,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        expected_nonce=expected_nonce,
    )
    duplicates = tuple(f"header.{name}" for name in header_doc.duplicates) + tuple(
        f"payload.{name}" for name in payload_doc.duplicates
    )
    return IdentityReport(
        domain="jose",
        artifact_type="jwt_compact",
        findings=tuple(findings),
        duplicates=duplicates,
        metadata={
            "header": header,
            "claims": payload_doc.value,
            "signature_bytes": len(signature),
            "segments": 3,
        },
    )


def _check_jwe_parts(
    header: dict[str, object],
    encrypted_key: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
    findings: list[IdentityFinding],
) -> None:
    alg = header.get("alg")
    enc = header.get("enc")
    if alg not in _JWE_ALGS:
        _append(findings, _finding("jwe", "unsupported_key_algorithm", "high", f"alg is {alg!r}"))
    if enc not in _JWE_ENC:
        _append(findings, _finding("jwe", "unsupported_content_algorithm", "high", f"enc is {enc!r}"))
    else:
        _, expected_iv, expected_tag = _JWE_ENC[str(enc)]
        if len(iv) != expected_iv:
            _append(findings, _finding("jwe", "iv_length_mismatch", "high", f"{enc} IV is {len(iv)} bytes; expected {expected_iv}"))
        if len(tag) != expected_tag:
            _append(findings, _finding("jwe", "tag_length_mismatch", "high", f"{enc} tag is {len(tag)} bytes; expected {expected_tag}"))
    direct_agreement = alg in ("dir", "ECDH-ES")
    if direct_agreement and encrypted_key:
        _append(findings, _finding("jwe", "direct_with_encrypted_key", "high", f"{alg} JWE has a non-empty encrypted-key value"))
    if not direct_agreement and not encrypted_key:
        _append(findings, _finding("jwe", "missing_encrypted_key", "high", f"{alg!r} JWE has an empty encrypted-key value"))
    wraps_cek = isinstance(alg, str) and (
        re.fullmatch(r"A(?:128|192|256)KW", alg)
        or re.fullmatch(r"ECDH-ES\+A(?:128|192|256)KW", alg)
        or re.fullmatch(r"PBES2-HS(?:256|384|512)\+A(?:128|192|256)KW", alg)
    )
    if wraps_cek and enc in _JWE_ENC and encrypted_key:
        expected_wrapped = _JWE_ENC[str(enc)][0] + 8
        if len(encrypted_key) != expected_wrapped:
            _append(findings, _finding(
                "jwe", "encrypted_key_length_mismatch", "high",
                f"{alg} wrapped key is {len(encrypted_key)} bytes; {enc} CEK wrapping expects {expected_wrapped}",
            ))
    if not ciphertext:
        _append(findings, _finding("jwe", "empty_ciphertext", "high", "ciphertext is empty"))
    if isinstance(alg, str) and alg.startswith("ECDH-ES"):
        epk = header.get("epk")
        if not isinstance(epk, dict):
            _append(findings, _finding("jwe", "missing_ephemeral_key", "high", "ECDH-ES header lacks epk"))
        else:
            epk_kty = epk.get("kty")
            epk_curve = epk.get("crv")
            epk_x = _jwk_member(epk, "x")
            expected_x = (
                _CURVE_LENGTHS.get(epk_curve) if epk_kty == "EC"
                else _OKP_LENGTHS.get(epk_curve) if epk_kty == "OKP"
                else None
            )
            epk_y = _jwk_member(epk, "y") if epk_kty == "EC" else b""
            if (
                expected_x is None
                or epk_x is None
                or len(epk_x) != expected_x
                or (epk_kty == "EC" and (epk_y is None or len(epk_y) != expected_x))
                or "d" in epk
            ):
                _append(findings, _finding("jwe", "invalid_ephemeral_key", "high", "ECDH-ES epk has invalid public key shape/length"))
    if isinstance(alg, str) and alg.startswith("PBES2-"):
        p2c = header.get("p2c")
        if isinstance(p2c, bool) or not isinstance(p2c, int) or not 1 <= p2c <= 1_000_000:
            _append(findings, _finding("jwe", "invalid_p2c", "high", f"PBES2 p2c is {p2c!r}"))
        if not isinstance(header.get("p2s"), str):
            _append(findings, _finding("jwe", "missing_p2s", "high", "PBES2 header lacks p2s"))
        else:
            try:
                p2s = _b64u_decode(str(header["p2s"]), label="PBES2 p2s", limit=1024)
            except IdentityInputError:
                p2s = b""
            if len(p2s) < 8:
                _append(findings, _finding("jwe", "invalid_p2s", "high", "PBES2 p2s is invalid or shorter than 8 bytes"))
    if header.get("zip") not in (None, "DEF"):
        _append(findings, _finding("jwe", "unsupported_compression", "medium", f"zip is {header.get('zip')!r}"))


def _analyze_compact_jwe(token: str) -> IdentityReport:
    parts = token.split(".")
    if len(parts) != 5:
        raise IdentityInputError("compact JWE must contain five segments")
    protected_doc = _json_segment(parts[0], label="JWE protected header")
    if not isinstance(protected_doc.value, dict):
        raise IdentityInputError("JWE protected header must be an object")
    encrypted_key = _b64u_decode(parts[1], label="JWE encrypted key")
    iv = _b64u_decode(parts[2], label="JWE IV")
    ciphertext = _b64u_decode(parts[3], label="JWE ciphertext")
    tag = _b64u_decode(parts[4], label="JWE tag")
    findings = _duplicate_findings("jwe", "protected header", protected_doc.duplicates)
    _check_crit(protected_doc.value, "jwe", findings)
    _header_trust_findings(protected_doc.value, findings, "jwe")
    _check_jwe_parts(protected_doc.value, encrypted_key, iv, ciphertext, tag, findings)
    return IdentityReport(
        domain="jose",
        artifact_type="jwe_compact",
        findings=tuple(findings),
        duplicates=tuple(f"protected.{name}" for name in protected_doc.duplicates),
        metadata={
            "protected": protected_doc.value,
            "encrypted_key_bytes": len(encrypted_key),
            "iv_bytes": len(iv),
            "ciphertext_bytes": len(ciphertext),
            "tag_bytes": len(tag),
            "segments": 5,
        },
    )


def _merge_headers(
    protected: dict[str, object],
    unprotected: object,
    recipient: object,
    findings: list[IdentityFinding],
) -> dict[str, object]:
    merged = dict(protected)
    for label, source in (("unprotected", unprotected), ("recipient", recipient)):
        if source is None:
            continue
        if not isinstance(source, dict):
            _append(findings, _finding("jose", "invalid_header_object", "high", f"{label} header is not an object"))
            continue
        for key, value in source.items():
            if key in merged:
                _append(findings, _finding(
                    "jose", "duplicate_header_parameter", "high", f"parameter {key!r} appears in multiple JOSE headers",
                    "the producer and verifier may apply different protected/unprotected precedence",
                ))
            else:
                merged[key] = value
    return merged


def _analyze_jwe_json(doc: _JsonDocument) -> IdentityReport:
    if not isinstance(doc.value, dict):
        raise IdentityInputError("JWE JSON serialization must be an object")
    obj = doc.value
    protected_segment = obj.get("protected", "")
    if not isinstance(protected_segment, str):
        raise IdentityInputError("JWE protected member must be base64url text")
    protected_doc = _json_segment(protected_segment, label="JWE protected header") if protected_segment else _JsonDocument({}, ())
    if not isinstance(protected_doc.value, dict):
        raise IdentityInputError("JWE protected header must be an object")
    findings = _duplicate_findings("jwe", "JWE JSON", doc.duplicates)
    findings.extend(_duplicate_findings("jwe", "protected header", protected_doc.duplicates))
    iv = _b64u_decode(obj.get("iv", "") if isinstance(obj.get("iv", ""), str) else "!", label="JWE IV")
    ciphertext = _b64u_decode(obj.get("ciphertext", "") if isinstance(obj.get("ciphertext", ""), str) else "!", label="JWE ciphertext")
    tag = _b64u_decode(obj.get("tag", "") if isinstance(obj.get("tag", ""), str) else "!", label="JWE tag")
    recipient_rows: list[dict[str, object]]
    if "recipients" in obj:
        recipients = obj["recipients"]
        if not isinstance(recipients, list) or not recipients or len(recipients) > MAX_KEYS:
            raise IdentityInputError("JWE recipients must be a bounded non-empty array")
        recipient_rows = [item for item in recipients if isinstance(item, dict)]
        if len(recipient_rows) != len(recipients):
            _append(findings, _finding("jwe", "invalid_recipient", "high", "one or more recipients are not objects"))
    else:
        recipient_rows = [{"header": obj.get("header"), "encrypted_key": obj.get("encrypted_key", "")}]
    recipient_meta: list[dict[str, object]] = []
    for index, recipient in enumerate(recipient_rows):
        header = _merge_headers(protected_doc.value, obj.get("unprotected"), recipient.get("header"), findings)
        encrypted_value = recipient.get("encrypted_key", "")
        if not isinstance(encrypted_value, str):
            raise IdentityInputError("JWE encrypted_key must be base64url text")
        encrypted_key = _b64u_decode(encrypted_value, label="JWE encrypted key")
        _check_jwe_parts(header, encrypted_key, iv, ciphertext, tag, findings)
        recipient_meta.append({"index": index, "header": header, "encrypted_key_bytes": len(encrypted_key)})
    duplicates = tuple(f"json.{name}" for name in doc.duplicates) + tuple(
        f"protected.{name}" for name in protected_doc.duplicates
    )
    return IdentityReport(
        domain="jose",
        artifact_type="jwe_json",
        findings=tuple(findings),
        duplicates=duplicates,
        metadata={
            "protected": protected_doc.value,
            "recipients": recipient_meta,
            "iv_bytes": len(iv),
            "ciphertext_bytes": len(ciphertext),
            "tag_bytes": len(tag),
        },
    )


def _analyze_jws_json(
    doc: _JsonDocument,
    *,
    now: float | None,
    expected_issuer: str | None,
    expected_audience: str | None,
    expected_nonce: str | None,
) -> IdentityReport:
    if not isinstance(doc.value, dict):
        raise IdentityInputError("JWS JSON serialization must be an object")
    obj = doc.value
    payload_segment = obj.get("payload")
    if not isinstance(payload_segment, str):
        raise IdentityInputError("JWS JSON payload must be base64url text")
    if "signatures" in obj:
        signatures = obj["signatures"]
        if not isinstance(signatures, list) or not signatures or len(signatures) > MAX_KEYS:
            raise IdentityInputError("JWS signatures must be a bounded non-empty array")
        signature_rows = signatures
    else:
        signature_rows = [{"protected": obj.get("protected", ""), "header": obj.get("header"), "signature": obj.get("signature", "")}]
    findings = _duplicate_findings("jws", "JWS JSON", doc.duplicates)
    meta: list[dict[str, object]] = []
    payload_doc: _JsonDocument | None = None
    protected_duplicates: list[str] = []
    for index, signature_row in enumerate(signature_rows):
        if not isinstance(signature_row, dict):
            _append(findings, _finding("jws", "invalid_signature_entry", "high", f"signature entry {index} is not an object"))
            continue
        protected_segment = signature_row.get("protected", "")
        if not isinstance(protected_segment, str):
            raise IdentityInputError("JWS protected member must be base64url text")
        protected_doc = _json_segment(protected_segment, label="JWS protected header") if protected_segment else _JsonDocument({}, ())
        if not isinstance(protected_doc.value, dict):
            raise IdentityInputError("JWS protected header must be an object")
        protected_duplicates.extend(f"signature[{index}].protected.{name}" for name in protected_doc.duplicates)
        findings.extend(_duplicate_findings("jws", f"signature[{index}] protected header", protected_doc.duplicates))
        header = _merge_headers(protected_doc.value, signature_row.get("header"), None, findings)
        signature_value = signature_row.get("signature", "")
        if not isinstance(signature_value, str):
            raise IdentityInputError("JWS signature must be base64url text")
        signature = _b64u_decode(signature_value, label="JWS signature", limit=2048)
        _check_crit(header, "jws", findings)
        _check_jws_signature(header.get("alg"), signature, findings, "jws")
        _header_trust_findings(header, findings, "jws")
        meta.append({"index": index, "header": header, "signature_bytes": len(signature)})
        if payload_doc is None:
            if header.get("b64") is False and "b64" in (header.get("crit") or []):
                payload_doc = _safe_json(payload_segment, label="unencoded JWS payload")
            else:
                payload_doc = _json_segment(payload_segment, label="JWS payload")
    if payload_doc is not None and isinstance(payload_doc.value, dict):
        findings.extend(_duplicate_findings("jws", "JWS payload", payload_doc.duplicates))
        _check_claims(
            payload_doc.value, findings, domain="jws", now=now,
            expected_issuer=expected_issuer, expected_audience=expected_audience,
            expected_nonce=expected_nonce,
        )
    return IdentityReport(
        domain="jose",
        artifact_type="jws_json",
        findings=tuple(findings),
        duplicates=tuple(f"json.{name}" for name in doc.duplicates) + tuple(protected_duplicates),
        metadata={"signatures": meta, "claims": payload_doc.value if payload_doc else None},
    )


def _jwk_member(jwk: dict[str, object], name: str, *, limit: int = 4096) -> bytes | None:
    value = jwk.get(name)
    if not isinstance(value, str):
        return None
    try:
        return _b64u_decode(value, label=f"JWK {name}", limit=limit)
    except IdentityInputError:
        return None


def _alg_matches_kty(alg: str, kty: object) -> bool:
    return (
        (alg.startswith("HS") and kty == "oct")
        or (alg.startswith(("RS", "PS", "RSA-OAEP")) and kty == "RSA")
        or (alg.startswith("ES") and kty == "EC")
        or (alg == "EdDSA" and kty == "OKP")
        or (alg.startswith(("A128", "A192", "A256", "PBES2")) and kty == "oct")
        or (alg.startswith("ECDH-ES") and kty in ("EC", "OKP"))
    )


def _analyze_jwk_document(doc: _JsonDocument) -> IdentityReport:
    if not isinstance(doc.value, dict):
        raise IdentityInputError("JWK/JWKS must be an object")
    obj = doc.value
    if "keys" in obj:
        keys = obj["keys"]
        if not isinstance(keys, list) or not keys or len(keys) > MAX_KEYS:
            raise IdentityInputError(f"JWKS keys must be a bounded non-empty array (max {MAX_KEYS})")
        artifact_type = "jwks"
    else:
        keys = [obj]
        artifact_type = "jwk"
    findings = _duplicate_findings("jwk", artifact_type.upper(), doc.duplicates)
    summaries: list[dict[str, object]] = []
    kids: dict[str, list[int]] = {}
    materials: dict[tuple[object, ...], list[int]] = {}
    for index, key in enumerate(keys):
        if not isinstance(key, dict):
            _append(findings, _finding("jwk", "non_object_key", "high", f"key {index} is not an object"))
            continue
        kty = key.get("kty")
        alg = key.get("alg")
        kid = key.get("kid")
        summary: dict[str, object] = {"index": index, "kty": kty, "alg": alg, "kid": kid, "use": key.get("use")}
        summaries.append(summary)
        if kty not in ("RSA", "EC", "OKP", "oct"):
            _append(findings, _finding("jwk", "unsupported_kty", "high", f"key {index} kty is {kty!r}"))
        if isinstance(alg, str) and not _alg_matches_kty(alg, kty):
            _append(findings, _finding("jwk", "alg_kty_mismatch", "high", f"key {index} alg {alg!r} conflicts with kty {kty!r}"))
        signature_alg = isinstance(alg, str) and alg in _KNOWN_JWS_ALGS and alg != "none"
        encryption_alg = isinstance(alg, str) and (alg in _JWE_ALGS or alg in _JWE_ENC)
        if key.get("use") == "sig" and encryption_alg:
            _append(findings, _finding("jwk", "use_alg_mismatch", "high", f"key {index} use=sig conflicts with alg {alg!r}"))
        if key.get("use") == "enc" and signature_alg:
            _append(findings, _finding("jwk", "use_alg_mismatch", "high", f"key {index} use=enc conflicts with alg {alg!r}"))
        if isinstance(kid, str):
            kids.setdefault(kid, []).append(index)
            if not kid:
                _append(findings, _finding("jwk", "empty_kid", "medium", f"key {index} has an empty kid"))
            if "/" in kid or "\\" in kid or "://" in kid or ".." in kid:
                _append(findings, _finding(
                    "jwk", "structured_kid", "medium", f"key {index} kid contains path/URL syntax",
                    "the relying implementation must use kid in a path/URL/query-like lookup",
                ))
        private_members = [name for name in ("d", "p", "q", "dp", "dq", "qi", "oth") if name in key]
        if private_members:
            _append(findings, _finding("jwk", "private_key_material", "high", f"key {index} exposes {private_members}"))
        key_ops = key.get("key_ops")
        if key_ops is not None:
            if not isinstance(key_ops, list) or any(not isinstance(item, str) for item in key_ops):
                _append(findings, _finding("jwk", "invalid_key_ops", "high", f"key {index} key_ops is not a string array"))
            else:
                if len(key_ops) != len(set(key_ops)):
                    _append(findings, _finding("jwk", "duplicate_key_ops", "medium", f"key {index} repeats key_ops"))
                if key.get("use") == "sig" and any(item in key_ops for item in ("encrypt", "decrypt", "wrapKey", "unwrapKey")):
                    _append(findings, _finding("jwk", "use_key_ops_mismatch", "high", f"key {index} use=sig conflicts with key_ops"))
                if key.get("use") == "enc" and any(item in key_ops for item in ("sign", "verify")):
                    _append(findings, _finding("jwk", "use_key_ops_mismatch", "high", f"key {index} use=enc conflicts with key_ops"))
                if signature_alg and any(item in key_ops for item in ("encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits")):
                    _append(findings, _finding("jwk", "alg_key_ops_mismatch", "high", f"key {index} signature alg conflicts with key_ops"))
                if encryption_alg and any(item in key_ops for item in ("sign", "verify")):
                    _append(findings, _finding("jwk", "alg_key_ops_mismatch", "high", f"key {index} encryption alg conflicts with key_ops"))
        if kty == "RSA":
            modulus = _jwk_member(key, "n", limit=16_384)
            exponent = _jwk_member(key, "e", limit=16)
            if modulus is None or exponent is None:
                _append(findings, _finding("jwk", "invalid_rsa_members", "high", f"key {index} lacks valid n/e"))
            else:
                bits = int.from_bytes(modulus, "big").bit_length()
                exp = int.from_bytes(exponent, "big")
                summary.update({"bits": bits, "exponent": exp})
                if bits < 2048:
                    _append(findings, _finding("jwk", "weak_rsa_modulus", "high", f"key {index} RSA modulus is {bits} bits"))
                if exp < 3 or exp % 2 == 0:
                    _append(findings, _finding("jwk", "invalid_rsa_exponent", "high", f"key {index} RSA exponent is {exp}"))
            material = (kty, key.get("n"), key.get("e"))
        elif kty == "EC":
            curve = key.get("crv")
            x = _jwk_member(key, "x")
            y = _jwk_member(key, "y")
            expected = _CURVE_LENGTHS.get(curve) if isinstance(curve, str) else None
            if expected is None or x is None or y is None or len(x) != expected or len(y) != expected:
                _append(findings, _finding("jwk", "invalid_ec_point_length", "high", f"key {index} curve/coordinate lengths are inconsistent"))
            if isinstance(alg, str) and alg.startswith("ES"):
                curve_alg = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}.get(alg)
                if curve_alg is not None and curve != curve_alg:
                    _append(findings, _finding("jwk", "alg_curve_mismatch", "high", f"key {index} {alg} uses {curve!r}"))
            material = (kty, curve, key.get("x"), key.get("y"))
        elif kty == "OKP":
            curve = key.get("crv")
            x = _jwk_member(key, "x")
            expected = _OKP_LENGTHS.get(curve) if isinstance(curve, str) else None
            if expected is None or x is None or len(x) != expected:
                _append(findings, _finding("jwk", "invalid_okp_length", "high", f"key {index} OKP curve/key length is inconsistent"))
            material = (kty, curve, key.get("x"))
        elif kty == "oct":
            secret = _jwk_member(key, "k", limit=4096)
            bits = len(secret) * 8 if secret is not None else 0
            summary["bits"] = bits
            _append(findings, _finding(
                "jwk", "symmetric_key_material", "high", f"key {index} contains an octet secret",
                "the artifact must be handled as secret key material and must not be a public JWKS",
            ))
            required = int(alg[2:]) if isinstance(alg, str) and re.fullmatch(r"HS(?:256|384|512)", alg) else 128
            if bits < required:
                _append(findings, _finding("jwk", "short_symmetric_key", "high", f"key {index} is {bits} bits; expected at least {required}"))
            material = (kty, key.get("k"))
        else:
            material = (kty, index)
        materials.setdefault(material, []).append(index)
        if isinstance(key.get("x5u"), str):
            _append(findings, _finding(
                "jwk", "remote_certificate_locator", "medium", f"key {index} contains x5u",
                "the verifier would have to fetch or trust this unconfigured certificate location",
            ))
    for kid, indexes in kids.items():
        if len(indexes) > 1:
            _append(findings, _finding(
                "jwk", "duplicate_kid", "high", f"kid {kid!r} appears at indexes {indexes}",
                "key selection behavior must be defined when multiple keys share a kid",
            ))
    for indexes in materials.values():
        if len(indexes) > 1:
            _append(findings, _finding("jwk", "duplicate_key_material", "medium", f"same public/key material appears at indexes {indexes}"))
    return IdentityReport(
        domain="jose",
        artifact_type=artifact_type,
        findings=tuple(findings),
        duplicates=tuple(f"json.{name}" for name in doc.duplicates),
        metadata={"keys": summaries, "key_count": len(keys)},
    )


def analyze_jose(
    artifact: object,
    *,
    now: float | None = None,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    expected_nonce: str | None = None,
) -> IdentityReport:
    """Statically inspect compact/JSON JOSE or JWK material without keys."""

    now = _validated_now(now)
    expected_issuer = _expected_text(expected_issuer, label="expected_issuer")
    expected_audience = _expected_text(expected_audience, label="expected_audience")
    expected_nonce = _expected_text(expected_nonce, label="expected_nonce")
    text = _bounded_text(artifact, label="JOSE artifact", byte_limit=MAX_TOKEN_CHARS)
    stripped = text.strip()
    if not stripped:
        raise IdentityInputError("JOSE artifact is empty")
    dot_count = stripped.count(".")
    if dot_count == 2 and not stripped.startswith("{"):
        return _analyze_compact_jwt(
            stripped, now=now, expected_issuer=expected_issuer,
            expected_audience=expected_audience, expected_nonce=expected_nonce,
        )
    if dot_count == 4 and not stripped.startswith("{"):
        return _analyze_compact_jwe(stripped)
    doc = _safe_json(stripped, label="JOSE JSON")
    if not isinstance(doc.value, dict):
        raise IdentityInputError("JOSE JSON must be an object")
    if "keys" in doc.value or "kty" in doc.value:
        return _analyze_jwk_document(doc)
    if "ciphertext" in doc.value and "tag" in doc.value:
        return _analyze_jwe_json(doc)
    if "payload" in doc.value and ("signature" in doc.value or "signatures" in doc.value):
        return _analyze_jws_json(
            doc, now=now, expected_issuer=expected_issuer,
            expected_audience=expected_audience, expected_nonce=expected_nonce,
        )
    raise IdentityInputError("unrecognized JOSE/JWK artifact")


_ATTR_RE = re.compile(r"(?P<name>[A-Za-z_][\w:.-]*)\s*=\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)", re.S)
_ASSERTION_OPEN_RE = re.compile(r"<(?:(?:saml|saml2):)?Assertion\b(?P<attrs>[^<>]{0,8192})>", re.I)
_ASSERTION_BLOCK_RE = re.compile(r"<(?:(?:saml|saml2):)?Assertion\b[^>]*>.*?</(?:(?:saml|saml2):)?Assertion\s*>", re.I | re.S)
_SIGNATURE_RE = re.compile(r"<(?:(?:ds):)?Signature\b", re.I)
_REFERENCE_RE = re.compile(r"<(?:(?:ds):)?Reference\b(?P<attrs>[^<>]{0,8192})>", re.I)
_ISSUER_RE = re.compile(r"<(?:(?:saml|saml2):)?Issuer\b[^>]*>\s*([^<]{0,2048}?)\s*</(?:(?:saml|saml2):)?Issuer\s*>", re.I)
_AUDIENCE_RE = re.compile(r"<(?:(?:saml|saml2):)?Audience\b[^>]*>\s*([^<]{0,2048}?)\s*</(?:(?:saml|saml2):)?Audience\s*>", re.I)


def _attrs(text: str) -> tuple[tuple[str, str], ...]:
    rows = [(match.group("name"), match.group("value")) for match in _ATTR_RE.finditer(text)]
    if len(rows) > MAX_FIELDS:
        raise IdentityInputError(f"XML attribute cap exceeded ({MAX_FIELDS})")
    return tuple(rows)


def _attr_value(rows: tuple[tuple[str, str], ...], name: str) -> str | None:
    matches = [value for key, value in rows if key.casefold() == name.casefold()]
    return matches[0] if len(matches) == 1 else None


def analyze_saml(
    xml: object,
    *,
    expected_issuer: str | None = None,
    expected_destination: str | None = None,
    expected_audience: str | None = None,
    expected_in_response_to: str | None = None,
) -> IdentityReport:
    """Find SAML/XSW leads using bounded regex evidence only; no XML parser."""

    expected_issuer = _expected_text(expected_issuer, label="expected_issuer")
    expected_destination = _expected_text(expected_destination, label="expected_destination")
    expected_audience = _expected_text(expected_audience, label="expected_audience")
    expected_in_response_to = _expected_text(expected_in_response_to, label="expected_in_response_to")
    text = _bounded_text(xml, label="SAML artifact", byte_limit=MAX_XML_BYTES)
    findings: list[IdentityFinding] = []
    if re.search(r"<!DOCTYPE\b|<!ENTITY\b", text, re.I):
        _append(findings, _finding(
            "saml", "xml_declaration_surface", "medium", "DOCTYPE or ENTITY declaration is present",
            "the actual SAML XML parser would have to permit DTD/entity processing",
        ))
    assertion_opens = list(_ASSERTION_OPEN_RE.finditer(text))
    assertion_blocks = list(_ASSERTION_BLOCK_RE.finditer(text))
    signatures = list(_SIGNATURE_RE.finditer(text))
    ids: dict[str, list[str]] = {}
    duplicate_attrs: list[str] = []
    for tag_match in re.finditer(r"<[A-Za-z_][\w:.-]*\b(?P<attrs>[^<>]{0,8192})>", text):
        attrs = _attrs(tag_match.group("attrs"))
        names: set[str] = set()
        for name, value in attrs:
            folded = name.casefold()
            if folded in names:
                duplicate_attrs.append(name)
            names.add(folded)
            if folded in ("id", "xml:id"):
                ids.setdefault(value, []).append(name)
    for name in _ordered_unique(duplicate_attrs):
        _append(findings, _finding(
            "saml", "duplicate_attribute", "high", f"an element repeats attribute {name!r}",
            "different XML/SAML layers may resolve duplicate attributes differently",
        ))
    for value, names in ids.items():
        if len(names) > 1:
            _append(findings, _finding(
                "saml", "duplicate_id", "high", f"ID value {value!r} appears {len(names)} times as {names}",
                "signature reference and business-logic selection may resolve duplicate IDs differently",
            ))
    references: list[str] = []
    for match in _REFERENCE_RE.finditer(text):
        uri = _attr_value(_attrs(match.group("attrs")), "URI")
        if uri is None:
            _append(findings, _finding("saml", "missing_reference_uri", "high", "Signature Reference has no unique URI"))
            continue
        references.append(uri)
        if not uri.startswith("#"):
            _append(findings, _finding(
                "saml", "external_or_empty_reference", "high", f"Signature Reference URI is {uri!r}",
                "the verifier would have to permit a non-local or empty reference target",
            ))
            continue
        target = uri[1:]
        count = len(ids.get(target, []))
        if count == 0:
            _append(findings, _finding("saml", "missing_reference_target", "high", f"Reference target {target!r} is absent"))
        elif count > 1:
            _append(findings, _finding("saml", "ambiguous_reference_target", "high", f"Reference target {target!r} resolves to {count} IDs"))
    if not signatures:
        _append(findings, _finding(
            "saml", "missing_signature", "high", "no Signature element is present",
            "the relying party must require a signature for this message type and trust context",
        ))
    if len(assertion_opens) > 1:
        _append(findings, _finding(
            "saml", "multiple_assertions", "high", f"artifact contains {len(assertion_opens)} Assertion elements",
            "business logic and signature validation must select the same assertion",
        ))
    unsigned_blocks = sum(1 for block in assertion_blocks if not _SIGNATURE_RE.search(block.group(0)))
    if unsigned_blocks and signatures:
        _append(findings, _finding(
            "saml", "unsigned_assertion_with_signature_elsewhere", "high",
            f"{unsigned_blocks} Assertion block(s) lack an embedded Signature while a Signature exists elsewhere",
            "the relying party must accept assertion data not bound by the signature it validates",
        ))
    issuers = tuple(match.group(1).strip() for match in _ISSUER_RE.finditer(text))
    if expected_issuer is not None and expected_issuer not in issuers:
        _append(findings, _finding(
            "saml", "issuer_mismatch", "high", f"issuers {issuers!r} do not include {expected_issuer!r}",
            "the caller-supplied issuer is the exact configured identity-provider entity ID",
        ))
    if len(set(issuers)) > 1:
        _append(findings, _finding("saml", "multiple_issuers", "high", f"artifact contains distinct issuers {issuers!r}"))
    response_match = re.search(r"<(?:(?:samlp|saml2p):)?Response\b(?P<attrs>[^<>]{0,8192})>", text, re.I)
    response_attrs = _attrs(response_match.group("attrs")) if response_match else ()
    if expected_destination is not None:
        destination = _attr_value(response_attrs, "Destination")
        if destination != expected_destination:
            _append(findings, _finding(
                "saml", "destination_mismatch", "high", f"Destination is {destination!r}; expected {expected_destination!r}",
                "the supplied destination is the exact assertion-consumer URL for this response",
            ))
    if expected_in_response_to is not None:
        in_response_values = tuple(match.group("value") for match in _ATTR_RE.finditer(text) if match.group("name").casefold() == "inresponseto")
        if expected_in_response_to not in in_response_values:
            _append(findings, _finding(
                "saml", "in_response_to_mismatch", "high", f"InResponseTo values {in_response_values!r} omit expected request ID",
                "the response must correlate to the saved authentication request",
            ))
    audiences = tuple(match.group(1).strip() for match in _AUDIENCE_RE.finditer(text))
    if expected_audience is not None and expected_audience not in audiences:
        _append(findings, _finding(
            "saml", "audience_mismatch", "high", f"Audience values {audiences!r} omit {expected_audience!r}",
            "the supplied audience is the exact service-provider entity ID",
        ))
    duplicates = tuple(f"ID:{value}" for value, names in ids.items() if len(names) > 1) + tuple(
        f"attribute:{name}" for name in _ordered_unique(duplicate_attrs)
    )
    return IdentityReport(
        domain="saml",
        artifact_type="saml_xml_static",
        findings=tuple(findings),
        duplicates=duplicates,
        metadata={
            "assertions": len(assertion_opens),
            "signatures": len(signatures),
            "references": references,
            "ids": list(ids),
            "issuers": list(issuers),
            "audiences": list(audiences),
            "parser": "none-regex-only",
        },
    )


def _parse_fields(value: object, *, label: str) -> _Fields:
    text = _bounded_text(value, label=label, byte_limit=MAX_FLOW_CHARS).strip()
    if not text:
        return _Fields((), {}, ())
    duplicates: list[str] = []
    pairs: list[tuple[str, str]] = []
    def consume(target: str) -> None:
        target = target.strip()
        if not target:
            return
        if target.startswith("{"):
            doc = _safe_json(target, label=label)
            if not isinstance(doc.value, dict):
                raise IdentityInputError(f"{label} JSON must be an object")
            duplicates.extend(doc.duplicates)
            for key, item in doc.value.items():
                if isinstance(item, (str, int, float, bool)) or item is None:
                    pairs.append((key, "" if item is None else str(item)))
                else:
                    raise IdentityInputError(f"{label} field {key!r} must be scalar")
            return
        try:
            pairs.extend(parse_qsl(target, keep_blank_values=True, strict_parsing=False, max_num_fields=MAX_FIELDS))
        except ValueError as exc:
            raise IdentityInputError(f"invalid or over-cap {label} fields") from exc

    first_line = text.splitlines()[0] if text.splitlines() else text
    targets: list[str] = []
    request_match = re.match(r"^[A-Z]+\s+(\S+)\s+HTTP/\d(?:\.\d)?$", first_line)
    if request_match:
        targets.append(urlsplit(request_match.group(1)).query)
        body_parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
        if len(body_parts) == 2:
            targets.append(body_parts[1])
    elif re.match(r"^HTTP/\d(?:\.\d)?\s+\d{3}\b", first_line):
        body_parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
        if len(body_parts) == 2:
            targets.append(body_parts[1])
    elif text.startswith("{"):
        targets.append(text)
    elif "?" in text or text.startswith(("http://", "https://")):
        targets.append(urlsplit(text).query)
    else:
        targets.append(text)
    for target in targets:
        consume(target)
    if len(pairs) > MAX_FIELDS:
        raise IdentityInputError(f"{label} field cap exceeded ({MAX_FIELDS})")
    values: dict[str, list[str]] = {}
    for key, item in pairs:
        values.setdefault(key, []).append(item)
    duplicates.extend(key for key, items in values.items() if len(items) > 1)
    return _Fields(
        tuple(pairs),
        {key: tuple(items) for key, items in values.items()},
        _ordered_unique(duplicates),
    )


def _flow_duplicate_findings(label: str, fields: _Fields) -> list[IdentityFinding]:
    return [
        _finding(
            "oauth", "duplicate_parameter", "high", f"{label} repeats parameter {name!r}",
            "authorization components may resolve duplicate parameters differently",
        )
        for name in fields.duplicates
    ]


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def analyze_oauth_flow(
    *,
    authorization_request: object = "",
    callback: object = "",
    token_request: object = "",
    token_response: object = "",
    expected_state: str | None = None,
    expected_nonce: str | None = None,
    expected_redirect_uri: str | None = None,
    expected_issuer: str | None = None,
    expected_client_id: str | None = None,
    now: float | None = None,
) -> IdentityReport:
    """Compare saved OAuth/OIDC flow artifacts without making or replaying a request."""

    expected_state = _expected_text(expected_state, label="expected_state")
    expected_nonce = _expected_text(expected_nonce, label="expected_nonce")
    expected_redirect_uri = _expected_text(expected_redirect_uri, label="expected_redirect_uri")
    expected_issuer = _expected_text(expected_issuer, label="expected_issuer")
    expected_client_id = _expected_text(expected_client_id, label="expected_client_id")
    now = _validated_now(now)
    auth = _parse_fields(authorization_request, label="authorization request")
    returned = _parse_fields(callback, label="authorization callback")
    token_req = _parse_fields(token_request, label="token request")
    token_res = _parse_fields(token_response, label="token response")
    findings: list[IdentityFinding] = []
    for label, fields in (("authorization request", auth), ("callback", returned), ("token request", token_req), ("token response", token_res)):
        findings.extend(_flow_duplicate_findings(label, fields))

    response_type = auth.one("response_type")
    response_types = set(response_type.split()) if response_type else set()
    client_id = auth.one("client_id")
    redirect_uri = auth.one("redirect_uri")
    state = auth.one("state")
    scope = set((auth.one("scope") or "").split())
    nonce = auth.one("nonce")
    challenge = auth.one("code_challenge")
    challenge_method = auth.one("code_challenge_method") or ("plain" if challenge else None)
    for required, value in (("response_type", response_type), ("client_id", client_id), ("redirect_uri", redirect_uri)):
        if value is None:
            _append(findings, _finding("oauth", "missing_authorization_parameter", "high", f"authorization request lacks unique {required}"))
    if state is None:
        _append(findings, _finding(
            "oauth", "missing_state", "high", "authorization request lacks a unique state",
            "the client must bind a fresh state value to the initiating browser session",
        ))
    elif len(state) < 16:
        _append(findings, _finding(
            "oauth", "short_state", "medium", f"state is only {len(state)} characters",
            "length alone does not prove entropy; the generator would also need to be unpredictable",
        ))
    if expected_state is not None and state != expected_state:
        _append(findings, _finding("oauth", "request_state_mismatch", "high", f"request state {state!r} differs from expected saved state"))
    if "openid" in scope and nonce is None:
        _append(findings, _finding("oidc", "missing_nonce", "high", "OpenID request lacks a unique nonce"))
    if expected_nonce is not None and nonce != expected_nonce:
        _append(findings, _finding("oidc", "request_nonce_mismatch", "high", f"request nonce {nonce!r} differs from expected saved nonce"))
    if "code" in response_types:
        if challenge is None:
            _append(findings, _finding(
                "oauth", "missing_pkce_challenge", "medium", "authorization-code request lacks code_challenge",
                "the client type and authorization-server policy must require PKCE for this flow",
            ))
        elif challenge_method != "S256":
            _append(findings, _finding(
                "oauth", "weak_pkce_method", "medium", f"code_challenge_method is {challenge_method!r}",
                "the authorization server must accept plain or an unknown PKCE method",
            ))
        if challenge is not None:
            valid_challenge = (
                re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge) is not None
                if challenge_method == "S256"
                else re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", challenge) is not None
            )
            if not valid_challenge:
                _append(findings, _finding(
                    "oauth", "invalid_pkce_challenge", "high",
                    f"code_challenge has invalid length/charset for {challenge_method!r}",
                ))
    if redirect_uri is not None:
        parsed_redirect = urlsplit(redirect_uri)
        if parsed_redirect.fragment:
            _append(findings, _finding("oauth", "redirect_has_fragment", "high", "redirect_uri contains a fragment"))
        if parsed_redirect.username or parsed_redirect.password:
            _append(findings, _finding("oauth", "redirect_has_userinfo", "high", "redirect_uri contains userinfo"))
    if expected_redirect_uri is not None and redirect_uri != expected_redirect_uri:
        _append(findings, _finding(
            "oauth", "redirect_mismatch", "high", f"redirect_uri is {redirect_uri!r}; expected exact {expected_redirect_uri!r}",
            "the caller-supplied URI is the registered exact redirect for this client",
        ))
    if expected_client_id is not None and client_id != expected_client_id:
        _append(findings, _finding("oauth", "client_id_mismatch", "high", f"client_id is {client_id!r}; expected {expected_client_id!r}"))

    callback_state = returned.one("state")
    state_anchor = expected_state if expected_state is not None else state
    if returned.pairs and callback_state != state_anchor:
        _append(findings, _finding(
            "oauth", "callback_state_mismatch", "high", f"callback state is {callback_state!r}; expected {state_anchor!r}",
            "the callback must belong to the same initiating browser session",
        ))
    callback_iss = returned.one("iss")
    if expected_issuer is not None and returned.pairs and callback_iss != expected_issuer:
        _append(findings, _finding(
            "oauth", "authorization_issuer_mismatch", "high", f"callback iss is {callback_iss!r}; expected {expected_issuer!r}",
            "the authorization response issuer parameter must be supported and bound to the selected issuer",
        ))
    if returned.pairs and returned.one("code") is None and returned.one("error") is None and returned.one("id_token") is None:
        _append(findings, _finding("oauth", "missing_callback_result", "high", "callback has no unique code, error, or id_token"))

    if token_req.pairs:
        if token_req.one("grant_type") != "authorization_code":
            _append(findings, _finding("oauth", "unexpected_grant_type", "high", f"token request grant_type is {token_req.one('grant_type')!r}"))
        callback_code = returned.one("code")
        if callback_code is not None and token_req.one("code") != callback_code:
            _append(findings, _finding("oauth", "authorization_code_mismatch", "high", "token request code differs from callback code"))
        if redirect_uri is not None and token_req.one("redirect_uri") != redirect_uri:
            _append(findings, _finding("oauth", "token_redirect_mismatch", "high", "token request redirect_uri differs from authorization request"))
        if client_id is not None and token_req.one("client_id") not in (None, client_id):
            _append(findings, _finding("oauth", "token_client_mismatch", "high", "token request client_id differs from authorization request"))
        verifier = token_req.one("code_verifier")
        if challenge is not None:
            if verifier is None:
                _append(findings, _finding("oauth", "missing_pkce_verifier", "high", "token request lacks code_verifier"))
            elif not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
                _append(findings, _finding("oauth", "invalid_pkce_verifier", "high", f"code_verifier length/charset is invalid ({len(verifier)} chars)"))
            else:
                derived = _pkce_s256(verifier) if challenge_method == "S256" else verifier
                if derived != challenge:
                    _append(findings, _finding("oauth", "pkce_mismatch", "high", "code_verifier does not reproduce saved code_challenge"))

    token_issuer = token_res.one("iss")
    if expected_issuer is not None and token_issuer is not None and token_issuer != expected_issuer:
        _append(findings, _finding("oidc", "token_response_issuer_mismatch", "high", f"token response iss is {token_issuer!r}"))
    if token_res.pairs and token_res.one("access_token") is not None:
        token_type = token_res.one("token_type")
        if token_type is None or token_type.casefold() != "bearer":
            _append(findings, _finding("oauth", "unexpected_token_type", "medium", f"token_type is {token_type!r}"))
    id_token = token_res.one("id_token") or returned.one("id_token")
    id_token_meta: dict[str, object] | None = None
    if id_token is not None:
        try:
            nested = analyze_jose(
                id_token,
                now=now,
                expected_issuer=expected_issuer,
                expected_audience=expected_client_id or client_id,
                expected_nonce=expected_nonce if expected_nonce is not None else nonce,
            )
            id_token_meta = nested.metadata
            for row in nested.findings:
                _append(findings, _finding(
                    "oidc", f"id_token.{row.code}", row.severity, row.evidence, row.precondition
                ))
        except IdentityInputError as exc:
            _append(findings, _finding("oidc", "invalid_id_token", "high", str(exc)))

    duplicates = tuple(
        f"{label}.{name}"
        for label, fields in (("authorization", auth), ("callback", returned), ("token_request", token_req), ("token_response", token_res))
        for name in fields.duplicates
    )
    return IdentityReport(
        domain="oauth_oidc",
        artifact_type="saved_flow",
        findings=tuple(findings),
        duplicates=duplicates,
        metadata={
            "authorization_fields": [name for name, _ in auth.pairs],
            "callback_fields": [name for name, _ in returned.pairs],
            "token_request_fields": [name for name, _ in token_req.pairs],
            "token_response_fields": [name for name, _ in token_res.pairs],
            "response_types": sorted(response_types),
            "scopes": sorted(scope),
            "pkce_method": challenge_method,
            "id_token": id_token_meta,
        },
    )


@dataclass(frozen=True)
class _MutationSpec:
    domain: str
    mutation: str
    preconditions: tuple[str, ...]


_MUTATIONS: tuple[_MutationSpec, ...] = (
    _MutationSpec("jose", "duplicate_protected_algorithm", ("a saved JOSE artifact exists", "the target parser's duplicate-field policy is known", "a human constructs any wire artifact separately")),
    _MutationSpec("jose", "signature_length_boundary", ("the expected algorithm is known", "the verifier reaches signature-length validation", "no signature is produced by this plan")),
    _MutationSpec("jose", "jwe_iv_tag_length_boundary", ("the declared enc algorithm is known", "the verifier parses the saved JWE", "no ciphertext or authentication tag is generated here")),
    _MutationSpec("jose", "duplicate_jwk_kid", ("the verifier selects keys by kid", "multiple saved/public keys can share an identifier", "no key is generated here")),
    _MutationSpec("saml", "duplicate_id_reference", ("the service consumes SAML", "signature validation and assertion selection may differ", "a human builds any XML only in an authorized sandbox")),
    _MutationSpec("saml", "unsigned_assertion_layout", ("a response-level or assertion signature is present", "business logic may select a different assertion", "this plan is not XML")),
    _MutationSpec("saml", "reference_target_mismatch", ("a signature Reference URI is present", "ID resolution behavior is known", "no signed XML is created here")),
    _MutationSpec("oauth", "state_mismatch", ("a saved authorization request/callback pair exists", "the client is expected to enforce browser-session state", "nothing is replayed")),
    _MutationSpec("oauth", "nonce_mismatch", ("an OIDC request and ID token are saved", "nonce binding is required", "no token is signed or replayed")),
    _MutationSpec("oauth", "redirect_exactness", ("the registered redirect is known", "a saved authorization request is available", "no URL/request is emitted")),
    _MutationSpec("oauth", "pkce_verifier_mismatch", ("a saved authorization and token request exist", "PKCE is required for the client", "only a comparison plan is emitted")),
    _MutationSpec("oauth", "issuer_mixup", ("multiple issuers are configured or plausible", "saved callback/token issuer evidence exists", "no authorization response is replayed")),
)


def build_mutation_skeletons(
    domain: str,
    *,
    mutation: str | None = None,
    marker: str = "R5D_MARKER",
) -> tuple[MutationSkeleton, ...]:
    """Return stable non-wire mutation plans for human review."""

    if domain not in ("jose", "saml", "oauth"):
        raise IdentityInputError("domain must be jose, saml, or oauth")
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise IdentityInputError("marker must be 4-64 safe ASCII characters")
    specs = [item for item in _MUTATIONS if item.domain == domain and (mutation is None or item.mutation == mutation)]
    if not specs:
        raise IdentityInputError(f"unknown {domain} mutation {mutation!r}")
    return tuple(
        MutationSkeleton(
            domain=item.domain,
            mutation=item.mutation,
            skeleton=(
                "R5D_INERT_MUTATION"
                f"|domain={item.domain}"
                f"|mutation={item.mutation}"
                f"|marker={marker}"
                "|input=SAVED_ARTIFACT_PLACEHOLDER"
                "|output=REVIEW_ONLY_NO_WIRE_ARTIFACT"
            ),
            marker=marker,
            evidence=(),
            preconditions=item.preconditions,
        )
        for item in specs
    )


def mutation_catalog(*, marker: str = "R5D_MARKER") -> tuple[MutationSkeleton, ...]:
    return tuple(
        plan
        for domain in ("jose", "saml", "oauth")
        for plan in build_mutation_skeletons(domain, marker=marker)
    )

