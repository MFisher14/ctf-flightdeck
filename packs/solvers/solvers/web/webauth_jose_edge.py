#!/usr/bin/env python3
"""Offline JOSE edge-case and implementation-risk analyzer.

This module complements the repository's full JOSE engines.  It focuses on
ECDSA P1363 component validity (including CVE-2022-21449), token-to-JWKS key
selection, header-supplied certificate trust, and non-path ``kid`` injection
syntax.  It never retrieves a key URL, guesses a secret, signs a token, or
replays an artifact.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    _HAVE_X509 = True
except ImportError:  # pragma: no cover - cryptography is a repository dependency
    _HAVE_X509 = False


MAX_TOKEN_BYTES = 512 * 1024
MAX_JSON_BYTES = 256 * 1024
MAX_JWKS_KEYS = 128
MAX_CERT_BYTES = 128 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_JSON_NODES = 20_000
MAX_JSON_DEPTH = 32


class WebauthJoseError(ValueError):
    """The supplied offline JOSE evidence is malformed, ambiguous, or over cap."""


_ECDSA = {
    "ES256": (
        32,
        int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        "P-256",
    ),
    "ES384": (
        48,
        int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
            "581A0DB248B0A77AECEC196ACCC52973",
            16,
        ),
        "P-384",
    ),
    "ES512": (
        66,
        int(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
            "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            16,
        ),
        "P-521",
    ),
}


_CVE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "id": "CVE-2022-21449",
        "implementation": "java-sunec",
        "affected": "Java 15/16; Java 17 < 17.0.3; Java 18 < 18.0.1",
        "class": "ECDSA verifier accepts the all-zero r=0,s=0 Psychic Signature",
        "reference": "https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/",
    },
    {
        "id": "CVE-2015-9235",
        "implementation": "node-jsonwebtoken",
        "affected": "< 4.2.2",
        "class": "algorithm/key-family confusion, including RSA public key as HMAC secret",
        "reference": "https://github.com/advisories/GHSA-c7hr-j4mj-j2w6",
    },
    {
        "id": "CVE-2017-11424",
        "implementation": "pyjwt",
        "affected": "< 1.5.1",
        "class": "incomplete asymmetric-key rejection in HMAC verification",
        "reference": "https://github.com/advisories/GHSA-r9jw-mwhq-wp62",
    },
    {
        "id": "CVE-2022-29217",
        "implementation": "pyjwt",
        "affected": ">= 1.5.0, < 2.4.0",
        "class": "algorithm confusion through unblocked SSH public-key encodings",
        "reference": "https://github.com/advisories/GHSA-ffqj-6fqr-9h24",
    },
)


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebauthJoseError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _strict_object(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        try:
            raw = json.dumps(dict(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
            raise WebauthJoseError(f"{label} is not bounded JSON") from exc
    elif isinstance(value, str):
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise WebauthJoseError(f"{label} is not UTF-8") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise WebauthJoseError(f"{label} must be a JSON object, text, or bytes")
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise WebauthJoseError(f"{label} is empty or exceeds {MAX_JSON_BYTES} bytes")
    try:
        parsed = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda item: (_ for _ in ()).throw(
                WebauthJoseError(f"{label} contains non-standard number {item}")
            ),
        )
    except WebauthJoseError:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise WebauthJoseError(f"invalid {label}") from exc
    if not isinstance(parsed, dict):
        raise WebauthJoseError(f"{label} must be a JSON object")
    stack: list[tuple[Any, int]] = [(parsed, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise WebauthJoseError(f"{label} exceeds JSON tree bounds")
        if isinstance(item, dict):
            for key, child in item.items():
                try:
                    key.encode("utf-8", "strict")
                except UnicodeError as exc:
                    raise WebauthJoseError(f"{label} contains a non-Unicode-scalar key") from exc
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8", "strict")
            except UnicodeError as exc:
                raise WebauthJoseError(f"{label} contains a non-Unicode-scalar string") from exc
        elif item is None or isinstance(item, (bool, int, float)):
            continue
        else:  # Defensive for caller-supplied Mapping subclasses.
            raise WebauthJoseError(f"{label} contains a non-JSON value")
    return parsed


def _b64url(value: str, label: str, limit: int) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2:
        raise WebauthJoseError(f"{label} is not bounded base64url text")
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise WebauthJoseError(f"{label} is not canonical unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise WebauthJoseError(f"invalid {label}") from exc
    if len(raw) > limit or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise WebauthJoseError(f"{label} is non-canonical or exceeds its cap")
    return raw


def _parse_version(value: str) -> tuple[int, ...]:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value)
    ):
        raise WebauthJoseError("version must be a final release with one to four dotted decimal components")
    try:
        return tuple(int(item) for item in value.split("."))
    except (ValueError, OverflowError) as exc:
        raise WebauthJoseError("version contains an invalid decimal component") from exc


def _before(version: tuple[int, ...], fixed: tuple[int, ...]) -> bool:
    width = max(len(version), len(fixed))
    return version + (0,) * (width - len(version)) < fixed + (0,) * (width - len(fixed))


def implementation_risks(implementation: str, version: str) -> tuple[dict[str, str], ...]:
    """Return catalog entries whose documented version bounds include the caller's version."""

    if not isinstance(implementation, str):
        raise WebauthJoseError("implementation must be text")
    name = implementation.strip().casefold()
    parsed = _parse_version(version)
    matched: list[dict[str, str]] = []
    if name == "node-jsonwebtoken" and _before(parsed, (4, 2, 2)):
        matched.append(dict(_CVE_CATALOG[1]))
    elif name == "pyjwt":
        if _before(parsed, (1, 5, 1)):
            matched.append(dict(_CVE_CATALOG[2]))
        if not _before(parsed, (1, 5, 0)) and _before(parsed, (2, 4, 0)):
            matched.append(dict(_CVE_CATALOG[3]))
    elif name in {"java-sunec", "sunec", "java"}:
        major = parsed[0]
        affected = major in {15, 16} or (major == 17 and _before(parsed, (17, 0, 3))) or (
            major == 18 and _before(parsed, (18, 0, 1))
        )
        if affected:
            matched.append(dict(_CVE_CATALOG[0]))
    elif name not in {item["implementation"] for item in _CVE_CATALOG}:
        raise WebauthJoseError(f"unknown implementation {implementation!r}")
    return tuple(matched)


def cve_catalog() -> tuple[dict[str, str], ...]:
    """Return the small, provenance-tagged implementation behavior catalog."""

    return tuple(dict(item) for item in _CVE_CATALOG)


def _kid_findings(kid: Any) -> list[dict[str, str]]:
    if kid is None:
        return []
    if not isinstance(kid, str):
        return [{"code": "kid_not_string", "severity": "high", "evidence": repr(kid)[:160]}]
    rows: list[dict[str, str]] = []

    def add(code: str, severity: str, evidence: str) -> None:
        rows.append({"code": code, "severity": severity, "evidence": evidence[:240]})

    if not kid or kid != kid.strip() or len(kid) > 256:
        add("kid_normalization_risk", "medium", f"length={len(kid)} stripped_equal={kid == kid.strip()}")
    if re.search(r"(?:\.\.|[/\\]|://|%2e|%2f|%5c)", kid, re.I):
        add("kid_path_or_url_syntax", "high", kid)
    if re.search(r"(?:['\";]|--|/\*|\bunion\s+select\b|\bor\s+['\"0-9])", kid, re.I):
        add("kid_sql_syntax", "high", kid)
    if re.search(r"[()*\\\x00]|(?:^|[,&|!])(?:cn|uid|objectClass)=", kid, re.I):
        add("kid_ldap_filter_syntax", "high", kid)
    if any(ord(char) < 32 or ord(char) == 127 for char in kid):
        add("kid_control_character", "high", repr(kid))
    if any(ord(char) > 127 for char in kid):
        add("kid_unicode_normalization", "medium", kid)
    return rows


def _alg_kty_match(alg: str, kty: Any) -> bool:
    return (
        (alg.startswith("HS") and kty == "oct")
        or (alg.startswith(("RS", "PS")) and kty == "RSA")
        or (alg.startswith("ES") and kty == "EC")
        or (alg == "EdDSA" and kty == "OKP")
    )


def _select_jwks(header: dict[str, Any], jwks: Any) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    document = _strict_object(jwks, "JWKS")
    keys = document.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_JWKS_KEYS:
        raise WebauthJoseError(f"JWKS keys must contain 1..{MAX_JWKS_KEYS} entries")
    if any(not isinstance(item, dict) for item in keys):
        raise WebauthJoseError("every JWKS key must be an object")
    kid = header.get("kid")
    selected = [item for item in keys if isinstance(kid, str) and item.get("kid") == kid]
    findings: list[dict[str, str]] = []
    if kid is None:
        findings.append({"code": "token_kid_missing", "severity": "medium", "evidence": f"JWKS has {len(keys)} keys"})
        if len(keys) == 1:
            selected = [keys[0]]
    if len(selected) != 1:
        findings.append({
            "code": "token_key_selection_ambiguous",
            "severity": "high",
            "evidence": f"kid={kid!r} selected {len(selected)} of {len(keys)} keys",
        })
    alg = header.get("alg")
    for key in selected:
        if isinstance(alg, str) and not _alg_kty_match(alg, key.get("kty")):
            findings.append({
                "code": "token_alg_key_family_mismatch",
                "severity": "critical",
                "evidence": f"alg={alg!r} selected kty={key.get('kty')!r}",
            })
        if isinstance(key.get("alg"), str) and key["alg"] != alg:
            findings.append({
                "code": "token_alg_key_policy_mismatch",
                "severity": "high",
                "evidence": f"token alg={alg!r}, JWK alg={key['alg']!r}",
            })
    summaries = [
        {name: key.get(name) for name in ("kid", "kty", "alg", "use")}
        for key in selected[:4]
    ]
    return findings, summaries


def _x5c_findings(header: dict[str, Any], expected_sha256: str | None) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256)
    ):
        raise WebauthJoseError("expected x5c SHA-256 fingerprint must be 64 hexadecimal characters")
    chain = header.get("x5c")
    if chain is None:
        if expected_sha256 is None:
            return [], []
        return [{
            "code": "x5c_expected_but_missing",
            "severity": "critical",
            "evidence": "a pinned leaf fingerprint was supplied but the JWS header has no x5c chain",
        }], []
    if not isinstance(chain, list) or not 1 <= len(chain) <= 16 or any(not isinstance(item, str) for item in chain):
        raise WebauthJoseError("x5c must be a bounded non-empty array of base64 certificates")
    findings = [{
        "code": "header_supplied_x5c",
        "severity": "medium" if expected_sha256 else "high",
        "evidence": f"header supplies {len(chain)} certificate(s); trust must be pinned outside the token",
    }]
    certificates: list[dict[str, Any]] = []
    for index, item in enumerate(chain):
        if len(item) > MAX_CERT_BYTES * 2:
            raise WebauthJoseError("x5c certificate exceeds encoded cap")
        try:
            der = base64.b64decode(item, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise WebauthJoseError(f"x5c[{index}] is not canonical base64") from exc
        if not der or len(der) > MAX_CERT_BYTES:
            raise WebauthJoseError(f"x5c[{index}] is empty or over cap")
        fingerprint = hashlib.sha256(der).hexdigest()
        row: dict[str, Any] = {"index": index, "sha256": fingerprint, "bytes": len(der)}
        if _HAVE_X509:
            try:
                cert = x509.load_der_x509_certificate(der)
                row.update({"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string()})
                if index == 0 and cert.subject == cert.issuer:
                    findings.append({
                        "code": "x5c_leaf_self_issued",
                        "severity": "medium",
                        "evidence": "leaf certificate subject equals issuer; cryptographic self-signature was not assumed",
                    })
                public = cert.public_key()
                alg = header.get("alg")
                if isinstance(alg, str) and alg.startswith("HS"):
                    findings.append({
                        "code": "x5c_hmac_key_confusion_shape",
                        "severity": "critical",
                        "evidence": f"{alg} is symmetric but x5c supplies {type(public).__name__} public-key material",
                    })
                elif isinstance(alg, str) and (
                    (alg.startswith(("RS", "PS")) and not isinstance(public, rsa.RSAPublicKey))
                    or (alg.startswith("ES") and not isinstance(public, ec.EllipticCurvePublicKey))
                ):
                    findings.append({
                        "code": "x5c_alg_key_family_mismatch",
                        "severity": "high",
                        "evidence": f"{alg} conflicts with leaf public key type {type(public).__name__}",
                    })
            except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
                raise WebauthJoseError(f"x5c[{index}] is not a valid DER certificate") from exc
        certificates.append(row)
    if expected_sha256 is not None and certificates[0]["sha256"].casefold() != expected_sha256.casefold():
        findings.append({
            "code": "x5c_leaf_fingerprint_mismatch",
            "severity": "critical",
            "evidence": f"leaf SHA-256 is {certificates[0]['sha256']}",
        })
    return findings, certificates


def _analyze_jws(
    token: str,
    *,
    jwks: Any | None = None,
    expected_x5c_sha256: str | None = None,
    implementation: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    """Analyze one compact JWS without verifying, signing, guessing, or fetching."""

    if not isinstance(token, str):
        raise WebauthJoseError("compact JWS must be text")
    try:
        encoded_size = len(token.encode("ascii", "strict"))
    except UnicodeError as exc:
        raise WebauthJoseError("compact JWS must be ASCII") from exc
    if not token or encoded_size > MAX_TOKEN_BYTES:
        raise WebauthJoseError(f"compact JWS is empty or exceeds {MAX_TOKEN_BYTES} bytes")
    parts = token.split(".")
    if len(parts) != 3:
        raise WebauthJoseError("compact JWS must contain exactly three segments")
    header = _strict_object(_b64url(parts[0], "protected header", MAX_JSON_BYTES), "protected header")
    payload_raw = _b64url(parts[1], "payload", MAX_JSON_BYTES)
    signature = _b64url(parts[2], "signature", MAX_TOKEN_BYTES)
    alg = header.get("alg")
    findings: list[dict[str, str]] = []
    signature_meta: dict[str, Any] = {"bytes": len(signature)}
    if not isinstance(alg, str) or not alg:
        findings.append({"code": "missing_algorithm", "severity": "high", "evidence": repr(alg)})
    elif alg == "none":
        findings.append({"code": "unsecured_algorithm", "severity": "critical", "evidence": "alg=none"})
    elif alg in _ECDSA:
        width, order, curve = _ECDSA[alg]
        signature_meta.update({"encoding": "IEEE-P1363", "component_bytes": width, "curve": curve})
        if len(signature) != width * 2:
            findings.append({
                "code": "ecdsa_signature_length",
                "severity": "high",
                "evidence": f"{alg} signature has {len(signature)} bytes; expected {width * 2}",
            })
        else:
            r_value = int.from_bytes(signature[:width], "big")
            s_value = int.from_bytes(signature[width:], "big")
            signature_meta.update({"r_zero": r_value == 0, "s_zero": s_value == 0})
            if r_value == 0 or s_value == 0:
                findings.append({
                    "code": "ecdsa_component_zero",
                    "severity": "critical",
                    "evidence": f"{alg} has r=0={r_value == 0}, s=0={s_value == 0}; ECDSA requires both components to be nonzero",
                })
            if r_value == 0 and s_value == 0:
                findings.append({
                    "code": "psychic_signature_all_zero",
                    "severity": "critical",
                    "evidence": f"{alg} has the documented all-zero CVE-2022-21449 Psychic Signature shape",
                })
            if not (1 <= r_value < order and 1 <= s_value < order):
                findings.append({
                    "code": "ecdsa_component_out_of_range",
                    "severity": "high",
                    "evidence": f"{alg} requires 1 <= r,s < curve order",
                })
    findings.extend(_kid_findings(header.get("kid")))
    selected_keys: list[dict[str, Any]] = []
    if jwks is not None:
        key_findings, selected_keys = _select_jwks(header, jwks)
        findings.extend(key_findings)
    x5c_findings, certificates = _x5c_findings(header, expected_x5c_sha256)
    findings.extend(x5c_findings)
    if "jwk" in header:
        findings.append({
            "code": "header_embedded_jwk",
            "severity": "high",
            "evidence": "verification key is supplied inside the token header",
        })
    implementation_matches: tuple[dict[str, str], ...] = ()
    if (implementation is None) != (version is None):
        raise WebauthJoseError("implementation and version must be supplied together")
    if implementation is not None and version is not None:
        implementation_matches = implementation_risks(implementation, version)
        for item in implementation_matches:
            findings.append({
                "code": "implementation_cve_match",
                "severity": "high",
                "evidence": f"{item['id']}: {item['affected']}",
            })
    payload_json: dict[str, Any] | None = None
    if payload_raw:
        try:
            payload_json = _strict_object(payload_raw, "JWS payload")
        except WebauthJoseError:
            payload_json = None
    return {
        "artifact": "compact_jws",
        "header": header,
        "payload_json": payload_json,
        "signature": signature_meta,
        "selected_keys": selected_keys,
        "certificates": certificates,
        "implementation_matches": list(implementation_matches),
        "findings": sorted(findings, key=lambda item: (item["code"], item["evidence"])),
        "verified": False,
        "offline": True,
        "network_requests": 0,
    }


def analyze_jws(
    token: str,
    *,
    jwks: Any | None = None,
    expected_x5c_sha256: str | None = None,
    implementation: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    """Analyze one compact JWS and expose only the declared input error."""

    try:
        return _analyze_jws(
            token,
            jwks=jwks,
            expected_x5c_sha256=expected_x5c_sha256,
            implementation=implementation,
            version=version,
        )
    except WebauthJoseError:
        raise
    except Exception as exc:
        raise WebauthJoseError("malformed JOSE evidence") from exc


def _read_bounded(path: str, label: str) -> bytes:
    try:
        value = Path(path)
        if not value.is_file() or value.stat().st_size > MAX_FILE_BYTES:
            raise WebauthJoseError(f"{label} is absent or exceeds {MAX_FILE_BYTES} bytes")
        with value.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except WebauthJoseError:
        raise
    except OSError as exc:
        raise WebauthJoseError(f"cannot read {label}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise WebauthJoseError(f"{label} exceeds {MAX_FILE_BYTES} bytes")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze one compact JWS")
    analyze.add_argument("token")
    analyze.add_argument("--jwks", help="local JWKS JSON file; never fetched")
    analyze.add_argument("--expected-x5c-sha256")
    analyze.add_argument("--implementation")
    analyze.add_argument("--version")
    sub.add_parser("catalog", help="print the implementation behavior catalog")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "catalog":
            result: Any = {"catalog": cve_catalog(), "offline": True, "network_requests": 0}
        else:
            jwks = _read_bounded(args.jwks, "JWKS") if args.jwks else None
            result = analyze_jws(
                args.token,
                jwks=jwks,
                expected_x5c_sha256=args.expected_x5c_sha256,
                implementation=args.implementation,
                version=args.version,
            )
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    except WebauthJoseError as exc:
        print(f"webauth_jose_edge: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
