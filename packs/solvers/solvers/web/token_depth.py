#!/usr/bin/env python3
"""Strict offline JWS/JWE/JWK verification and confusion diagnostics.

This complements ``auth_trust.py``: that module builds reviewable JWT trust
candidates, while this one authenticates supplied compact JOSE objects,
decrypts common JWE algorithms with explicit local keys, computes RFC 7638
thumbprints, and audits a supplied JWKS for ambiguous key selection.  No key
URL is fetched and no token is replayed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import zlib
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes, padding, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        ec, ed25519, padding as asym_padding, rsa, x25519,
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False


MAX_TOKEN = 8 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
MAX_KEYS = 10_000
MAX_P2C = 1_000_000
MAX_PLAINTEXT = 32 * 1024 * 1024


class TokenError(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise TokenError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _json(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_JSON:
        raise TokenError("JOSE JSON exceeds cap")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenError("invalid strict JOSE JSON") from exc
    if not isinstance(value, dict):
        raise TokenError("JOSE JSON must be an object")
    return value


def b64u_decode(value: str, *, limit: int = MAX_TOKEN) -> bytes:
    if not isinstance(value, str) or len(value) > limit * 2 or "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise TokenError("invalid base64url segment")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise TokenError("invalid base64url segment") from exc
    if len(raw) > limit or b64u_encode(raw) != value:
        raise TokenError("non-canonical or over-limit base64url segment")
    return raw


def b64u_encode(value: bytes) -> str:
    try:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    except TypeError as exc:
        raise TokenError("base64url input must be bytes-like") from exc


def parse_compact(value: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise TokenError("compact token is empty or over cap")
    try:
        encoded_value = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TokenError("compact token must be ASCII") from exc
    if len(encoded_value) > MAX_TOKEN:
        raise TokenError("compact token is empty or over cap")
    parts = value.split(".")
    if len(parts) not in (3, 5):
        raise TokenError("compact JOSE token must have three or five segments")
    protected_raw = b64u_decode(parts[0], limit=MAX_JSON)
    protected = _json(protected_raw)
    if len(parts) == 3:
        payload = b64u_decode(parts[1]) if protected.get("b64", True) is not False else parts[1].encode("ascii")
        signature = b64u_decode(parts[2])
        return {"kind": "jws", "protected": protected, "protected_raw": protected_raw,
                "payload": payload, "signature": signature, "segments": parts,
                "signing_input": (parts[0] + "." + parts[1]).encode("ascii")}
    return {"kind": "jwe", "protected": protected, "protected_raw": protected_raw,
            "encrypted_key": b64u_decode(parts[1]), "iv": b64u_decode(parts[2]),
            "ciphertext": b64u_decode(parts[3]), "tag": b64u_decode(parts[4]),
            "segments": parts, "aad": parts[0].encode("ascii")}


_ENC = {
    "A128GCM": (16, "gcm"), "A192GCM": (24, "gcm"), "A256GCM": (32, "gcm"),
    "A128CBC-HS256": (32, "cbc-hmac"), "A192CBC-HS384": (48, "cbc-hmac"),
    "A256CBC-HS512": (64, "cbc-hmac"),
}


def _load_private_key(value: Any):
    if not HAVE_CRYPTO:
        raise TokenError("cryptography is unavailable")
    if hasattr(value, "decrypt"):
        return value
    if isinstance(value, str):
        value = value.encode()
    if not isinstance(value, bytes) or len(value) > MAX_JSON:
        raise TokenError("private key must be a bounded PEM/DER value")
    try:
        return serialization.load_pem_private_key(value, password=None)
    except ValueError:
        try:
            return serialization.load_der_private_key(value, password=None)
        except ValueError as exc:
            raise TokenError("private key is not readable PEM/DER") from exc


_EC_CURVES = {
    "P-256": (ec.SECP256R1, 32),
    "P-384": (ec.SECP384R1, 48),
    "P-521": (ec.SECP521R1, 66),
} if HAVE_CRYPTO else {}


def _jwk_document(value: Any) -> dict[str, Any] | None:
    """Return a strict caller-supplied JWK, without ever following a URL."""
    if isinstance(value, dict):
        try:
            raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise TokenError("private JWK is not a JSON object") from exc
        return _json(raw)
    if isinstance(value, str):
        value = value.encode("utf-8")
    if isinstance(value, bytes) and value.lstrip().startswith(b"{"):
        return _json(value)
    return None


def _fixed_jwk_bytes(jwk: dict[str, Any], member: str, width: int) -> bytes:
    value = jwk.get(member)
    if not isinstance(value, str):
        raise TokenError(f"JWK lacks string member {member!r}")
    raw = b64u_decode(value, limit=max(width, 1024))
    if len(raw) != width:
        raise TokenError(f"JWK member {member!r} must contain exactly {width} bytes")
    return raw


def _ecdh_private_key(value: Any):
    """Load a local ECDH private key and reject inconsistent private/public JWKs."""
    if not HAVE_CRYPTO:
        raise TokenError("cryptography is unavailable")
    if isinstance(value, (ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey)):
        return value
    jwk = _jwk_document(value)
    if jwk is None:
        private = _load_private_key(value)
        if not isinstance(private, (ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey)):
            raise TokenError("ECDH-ES needs an EC or X25519 private key")
        return private
    if jwk.get("kty") == "EC":
        curve_info = _EC_CURVES.get(jwk.get("crv"))
        if curve_info is None:
            raise TokenError("unsupported ECDH EC JWK curve")
        curve_type, width = curve_info
        scalar = int.from_bytes(_fixed_jwk_bytes(jwk, "d", width), "big")
        try:
            private = ec.derive_private_key(scalar, curve_type())
        except (TypeError, ValueError) as exc:
            raise TokenError("invalid ECDH EC private scalar") from exc
        if "x" in jwk or "y" in jwk:
            if "x" not in jwk or "y" not in jwk:
                raise TokenError("EC private JWK must provide both x and y or neither")
            numbers = private.public_key().public_numbers()
            supplied = (int.from_bytes(_fixed_jwk_bytes(jwk, "x", width), "big"),
                        int.from_bytes(_fixed_jwk_bytes(jwk, "y", width), "big"))
            if supplied != (numbers.x, numbers.y):
                raise TokenError("EC private JWK public coordinates do not match d")
        return private
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "X25519":
        try:
            private = x25519.X25519PrivateKey.from_private_bytes(_fixed_jwk_bytes(jwk, "d", 32))
        except (TypeError, ValueError) as exc:
            raise TokenError("invalid X25519 private JWK") from exc
        if "x" in jwk:
            actual = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if not hmac.compare_digest(actual, _fixed_jwk_bytes(jwk, "x", 32)):
                raise TokenError("X25519 private JWK public key does not match d")
        return private
    raise TokenError("ECDH-ES private JWK must be EC or X25519")


def _ecdh_ephemeral_key(jwk: Any):
    if not isinstance(jwk, dict):
        raise TokenError("ECDH-ES requires an epk public JWK")
    if any(name in jwk for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k")):
        raise TokenError("ECDH-ES epk must not contain private key material")
    if jwk.get("kty") == "EC":
        curve_info = _EC_CURVES.get(jwk.get("crv"))
        if curve_info is None:
            raise TokenError("unsupported ECDH epk curve")
        curve_type, width = curve_info
        x = int.from_bytes(_fixed_jwk_bytes(jwk, "x", width), "big")
        y = int.from_bytes(_fixed_jwk_bytes(jwk, "y", width), "big")
        try:
            return ec.EllipticCurvePublicNumbers(x, y, curve_type()).public_key(), jwk["crv"]
        except (TypeError, ValueError) as exc:
            raise TokenError("ECDH epk point is not on the named curve") from exc
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "X25519":
        try:
            return x25519.X25519PublicKey.from_public_bytes(_fixed_jwk_bytes(jwk, "x", 32)), "X25519"
        except (TypeError, ValueError) as exc:
            raise TokenError("invalid X25519 epk") from exc
    raise TokenError("ECDH epk must be EC or X25519")


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise TokenError("ECDH Concat-KDF field exceeds the length cap")
    return len(value).to_bytes(4, "big") + value


def _concat_kdf_sha256(shared_secret: bytes, algorithm: str, apu: bytes, apv: bytes,
                       key_bits: int) -> bytes:
    """RFC 7518 Concat KDF (NIST SP 800-56A), fixed to the mandated SHA-256."""
    if (not isinstance(shared_secret, bytes) or not shared_secret or not isinstance(algorithm, str)
            or not algorithm or not 1 <= key_bits <= 512 or key_bits % 8):
        raise TokenError("invalid ECDH Concat-KDF inputs")
    try:
        algorithm_raw = algorithm.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TokenError("ECDH algorithm identifier must be ASCII") from exc
    other = (_length_prefixed(algorithm_raw) + _length_prefixed(apu)
             + _length_prefixed(apv) + key_bits.to_bytes(4, "big"))
    output = bytearray()
    for counter in range(1, (key_bits + 255) // 256 + 1):
        output.extend(hashlib.sha256(counter.to_bytes(4, "big") + shared_secret + other).digest())
    return bytes(output[:key_bits // 8])


def _ecdh_derived_key(header: dict[str, Any], key: Any, algorithm: str, key_bytes: int) -> bytes:
    private = _ecdh_private_key(key)
    public, curve_name = _ecdh_ephemeral_key(header.get("epk"))
    if isinstance(private, ec.EllipticCurvePrivateKey):
        if not isinstance(public, ec.EllipticCurvePublicKey) or private.curve.name != public.curve.name:
            raise TokenError("ECDH recipient and epk curves do not match")
        shared = private.exchange(ec.ECDH(), public)
    elif isinstance(private, x25519.X25519PrivateKey):
        if not isinstance(public, x25519.X25519PublicKey) or curve_name != "X25519":
            raise TokenError("X25519 recipient requires an X25519 epk")
        try:
            shared = private.exchange(public)
        except ValueError as exc:
            raise TokenError("invalid X25519 shared secret") from exc
    else:  # pragma: no cover
        raise TokenError("unsupported ECDH recipient key")
    party = []
    for name in ("apu", "apv"):
        value = header.get(name)
        if value is None:
            party.append(b"")
        elif isinstance(value, str):
            party.append(b64u_decode(value, limit=1024))
        else:
            raise TokenError(f"ECDH-ES {name} must be a base64url string")
    return _concat_kdf_sha256(shared, algorithm, party[0], party[1], key_bytes * 8)


def _cek(parsed: dict[str, Any], key: Any) -> bytes:
    header, encrypted = parsed["protected"], parsed["encrypted_key"]
    alg, enc = header.get("alg"), header.get("enc")
    if enc not in _ENC:
        raise TokenError("unsupported JWE content encryption algorithm")
    expected = _ENC[enc][0]
    if alg == "dir":
        if encrypted:
            raise TokenError("direct JWE must have an empty encrypted-key segment")
        if not isinstance(key, bytes) or len(key) != expected:
            raise TokenError(f"direct JWE key must contain {expected} bytes")
        return key
    if alg == "ECDH-ES":
        if encrypted:
            raise TokenError("direct ECDH-ES must have an empty encrypted-key segment")
        return _ecdh_derived_key(header, key, enc, expected)
    if isinstance(alg, str) and re.fullmatch(r"ECDH-ES\+A(128|192|256)KW", alg):
        match = re.fullmatch(r"ECDH-ES\+A(128|192|256)KW", alg)
        assert match is not None
        kek = _ecdh_derived_key(header, key, alg, int(match.group(1)) // 8)
        try:
            cek = aes_key_unwrap(kek, encrypted)
        except Exception as exc:
            raise TokenError("ECDH-ES AES key unwrap failed") from exc
    elif alg in ("A128KW", "A192KW", "A256KW"):
        if not HAVE_CRYPTO:
            raise TokenError("cryptography is unavailable")
        size = int(alg[1:4]) // 8
        if not isinstance(key, bytes) or len(key) != size:
            raise TokenError(f"{alg} key must contain {size} bytes")
        try:
            cek = aes_key_unwrap(key, encrypted)
        except Exception as exc:
            raise TokenError("AES key unwrap authentication failed") from exc
    elif alg in ("RSA-OAEP", "RSA-OAEP-256"):
        private = _load_private_key(key)
        digest = hashes.SHA1() if alg == "RSA-OAEP" else hashes.SHA256()
        try:
            cek = private.decrypt(encrypted, asym_padding.OAEP(
                mgf=asym_padding.MGF1(digest), algorithm=digest, label=None))
        except Exception as exc:
            raise TokenError("RSA-OAEP key unwrap failed") from exc
    elif isinstance(alg, str) and re.fullmatch(r"PBES2-HS(256|384|512)\+A(128|192|256)KW", alg):
        if not HAVE_CRYPTO:
            raise TokenError("cryptography is unavailable")
        if not isinstance(key, bytes) or not 1 <= len(key) <= 4096:
            raise TokenError("PBES2 password must be bounded bytes")
        p2s, p2c = header.get("p2s"), header.get("p2c")
        if not isinstance(p2s, str) or not isinstance(p2c, int) or not 1 <= p2c <= MAX_P2C:
            raise TokenError("PBES2 requires bounded p2s/p2c parameters")
        salt_input = b64u_decode(p2s, limit=1024)
        match = re.fullmatch(r"PBES2-HS(256|384|512)\+A(128|192|256)KW", alg)
        assert match is not None
        digest = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}[match.group(1)]()
        length = int(match.group(2)) // 8
        kek = PBKDF2HMAC(algorithm=digest, length=length, salt=alg.encode() + b"\x00" + salt_input,
                         iterations=p2c).derive(key)
        try:
            cek = aes_key_unwrap(kek, encrypted)
        except Exception as exc:
            raise TokenError("PBES2 key unwrap failed") from exc
    else:
        raise TokenError("unsupported JWE key-management algorithm")
    if len(cek) != expected:
        raise TokenError("unwrapped CEK has the wrong length")
    return cek


def _inflate(raw: bytes) -> bytes:
    for window in (-15, zlib.MAX_WBITS):
        try:
            obj = zlib.decompressobj(window)
            out = obj.decompress(raw, MAX_PLAINTEXT + 1)
            remaining = MAX_PLAINTEXT + 1 - len(out)
            if remaining <= 0:
                continue
            out += obj.flush(remaining)
            if obj.eof and not obj.unused_data and len(out) <= MAX_PLAINTEXT:
                return out
        except zlib.error:
            pass
    raise TokenError("JWE DEF payload is invalid or exceeds cap")


def decrypt_jwe(value: str, key: Any) -> dict[str, Any]:
    """Authenticate then decrypt a compact JWE using only caller-supplied key material."""
    parsed = parse_compact(value)
    if parsed["kind"] != "jwe":
        raise TokenError("token is not a compact JWE")
    if not HAVE_CRYPTO:
        raise TokenError("cryptography is unavailable")
    header, enc = parsed["protected"], parsed["protected"].get("enc")
    if header.get("crit") not in (None, []):
        raise TokenError("unsupported critical JWE header")
    cek = _cek(parsed, key)
    iv, ciphertext, tag, aad = parsed["iv"], parsed["ciphertext"], parsed["tag"], parsed["aad"]
    try:
        if _ENC[enc][1] == "gcm":
            if len(iv) != 12 or len(tag) != 16:
                raise TokenError("JWE GCM IV/tag length is invalid")
            plaintext = AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
        else:
            half = len(cek) // 2
            mac_key, encryption_key = cek[:half], cek[half:]
            digest = {16: hashlib.sha256, 24: hashlib.sha384, 32: hashlib.sha512}[half]
            al = (8 * len(aad)).to_bytes(8, "big")
            expected = hmac.new(mac_key, aad + iv + ciphertext + al, digest).digest()[:half]
            if len(iv) != 16 or len(tag) != half or not hmac.compare_digest(tag, expected):
                raise TokenError("JWE CBC-HMAC authentication failed")
            decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
    except TokenError:
        raise
    except Exception as exc:
        raise TokenError("JWE authentication/decryption failed") from exc
    if len(plaintext) > MAX_PLAINTEXT:
        raise TokenError("JWE plaintext exceeds cap")
    if header.get("zip") == "DEF":
        plaintext = _inflate(plaintext)
    elif header.get("zip") is not None:
        raise TokenError("unsupported JWE compression")
    nested = None
    cty = header.get("cty")
    if cty is not None and not isinstance(cty, str):
        raise TokenError("JWE cty must be a string")
    try:
        if (cty or "").upper() in ("JWT", "JOSE") or plaintext.count(b".") in (2, 4):
            nested = parse_compact(plaintext.decode("ascii"))
        else:
            nested = json.loads(plaintext)
    except (TokenError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {"verified": True, "protected": header, "plaintext": plaintext,
            "nested": nested, "offline": True, "requests_sent": 0}


_THUMBPRINT_FIELDS = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"),
                      "oct": ("k", "kty"), "OKP": ("crv", "kty", "x")}


def jwk_thumbprint(jwk: dict[str, Any], hash_name: str = "sha256") -> str:
    if not isinstance(jwk, dict) or jwk.get("kty") not in _THUMBPRINT_FIELDS:
        raise TokenError("unsupported JWK type")
    fields = _THUMBPRINT_FIELDS[jwk["kty"]]
    if any(not isinstance(jwk.get(name), str) or not jwk[name] for name in fields):
        raise TokenError("JWK lacks a thumbprint member")
    try:
        digest = hashlib.new(hash_name, json.dumps({name: jwk[name] for name in fields},
                                                   sort_keys=True, separators=(",", ":")).encode()).digest()
    except (TypeError, ValueError) as exc:
        raise TokenError("unsupported thumbprint hash") from exc
    return b64u_encode(digest)


def _jwk_material(jwk: dict[str, Any]):
    try:
        return jwk_thumbprint(jwk)
    except TokenError:
        return None


def assess_jwks(value: Any) -> dict[str, Any]:
    try:
        _bounded = json.loads(json.dumps(value))  # reject non-JSON host objects deterministically
    except (TypeError, ValueError, RecursionError) as exc:
        raise TokenError("JWKS must be JSON-compatible") from exc
    keys = _bounded.get("keys") if isinstance(_bounded, dict) else None
    if not isinstance(keys, list) or not keys or len(keys) > MAX_KEYS:
        raise TokenError("JWKS must contain a bounded non-empty keys list")
    findings, rows, by_kid, by_material = [], [], {}, {}
    for index, jwk in enumerate(keys):
        if not isinstance(jwk, dict):
            findings.append({"kind": "non_object_key", "index": index}); continue
        kid = jwk.get("kid") if isinstance(jwk.get("kid"), str) else None
        material = _jwk_material(jwk)
        row = {"index": index, "kid": kid, "kty": jwk.get("kty"), "alg": jwk.get("alg"),
               "use": jwk.get("use"), "key_ops": jwk.get("key_ops"), "thumbprint": material}
        rows.append(row)
        if kid is not None:
            by_kid.setdefault(kid, []).append(row)
        if material is not None:
            by_material.setdefault(material, []).append(row)
        if (any(name in jwk for name in ("d", "p", "q", "dp", "dq", "qi", "oth"))
                or (jwk.get("kty") == "oct" and "k" in jwk)):
            findings.append({"kind": "private_key_material", "index": index, "kid": kid})
        alg, kty = jwk.get("alg"), jwk.get("kty")
        if isinstance(alg, str):
            allowed = ((alg.startswith("HS") and kty == "oct") or
                       (alg.startswith(("RS", "PS")) and kty == "RSA") or
                       (alg.startswith("ES") and kty == "EC") or
                       (alg == "EdDSA" and kty == "OKP") or
                       (alg.startswith("ECDH-ES") and kty in ("EC", "OKP")) or
                       alg.startswith(("RSA-OAEP", "A", "PBES2")))
            if not allowed:
                findings.append({"kind": "alg_key_type_mismatch", "index": index, "kid": kid,
                                 "alg": alg, "kty": kty})
        if jwk.get("use") == "enc" and isinstance(alg, str) and alg.startswith(("HS", "RS", "PS", "ES")):
            findings.append({"kind": "use_alg_mismatch", "index": index, "kid": kid})
        if kty == "RSA" and isinstance(jwk.get("n"), str):
            try:
                bits = int.from_bytes(b64u_decode(jwk["n"], limit=1 << 20), "big").bit_length()
                row["bits"] = bits
                if bits < 2048:
                    findings.append({"kind": "weak_rsa_modulus", "index": index, "kid": kid, "bits": bits})
            except TokenError:
                findings.append({"kind": "invalid_key_encoding", "index": index, "member": "n"})
        if kty == "oct" and isinstance(jwk.get("k"), str):
            try:
                bits = len(b64u_decode(jwk["k"], limit=4096)) * 8
                row["bits"] = bits
                if bits < 256:
                    findings.append({"kind": "short_symmetric_key", "index": index, "kid": kid, "bits": bits})
            except TokenError:
                findings.append({"kind": "invalid_key_encoding", "index": index, "member": "k"})
    for kid, group in by_kid.items():
        if len(group) > 1:
            findings.append({"kind": "duplicate_kid", "kid": kid,
                             "indices": [row["index"] for row in group],
                             "different_material": len({row["thumbprint"] for row in group}) > 1})
    for material, group in by_material.items():
        kids = {row["kid"] for row in group}
        if len(group) > 1 and len(kids) > 1:
            findings.append({"kind": "same_key_multiple_kids", "thumbprint": material,
                             "kids": sorted(str(kid) for kid in kids)})
    return {"keys": rows, "findings": findings, "offline": True, "urls_fetched": 0}


def _public_key(jwk: dict[str, Any]):
    if not HAVE_CRYPTO:
        raise TokenError("cryptography is unavailable")
    kty = jwk.get("kty")
    if kty == "RSA":
        n, e = int.from_bytes(b64u_decode(jwk.get("n", "")), "big"), int.from_bytes(b64u_decode(jwk.get("e", "")), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}.get(jwk.get("crv"))
        if curve is None:
            raise TokenError("unsupported EC JWK curve")
        x, y = int.from_bytes(b64u_decode(jwk.get("x", "")), "big"), int.from_bytes(b64u_decode(jwk.get("y", "")), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve()).public_key()
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk.get("x", "")))
    raise TokenError("unsupported public JWK type")


def verify_jws(value: str, jwk: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_compact(value)
    if parsed["kind"] != "jws" or not isinstance(jwk, dict):
        raise TokenError("JWS and one JWK are required")
    header, alg = parsed["protected"], parsed["protected"].get("alg")
    if header.get("crit") not in (None, [], ["b64"]) or not isinstance(alg, str) or alg == "none":
        raise TokenError("unsupported/unsigned JWS algorithm")
    if jwk.get("alg") not in (None, alg):
        raise TokenError("JWS alg conflicts with JWK alg")
    signed, signature = parsed["signing_input"], parsed["signature"]
    verified = False
    try:
        if alg in ("HS256", "HS384", "HS512") and jwk.get("kty") == "oct":
            key = b64u_decode(jwk.get("k", ""), limit=4096)
            digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                      "HS512": hashlib.sha512}[alg]
            verified = hmac.compare_digest(signature, hmac.new(key, signed, digest).digest())
        elif alg.startswith("RS") or alg.startswith("PS"):
            digest = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}[alg[-3:]]()
            pad = asym_padding.PKCS1v15() if alg.startswith("RS") else asym_padding.PSS(
                mgf=asym_padding.MGF1(digest), salt_length=digest.digest_size)
            _public_key(jwk).verify(signature, signed, pad, digest); verified = True
        elif alg.startswith("ES"):
            size = {"ES256": 32, "ES384": 48, "ES512": 66}.get(alg)
            if size is None or len(signature) != size * 2:
                raise TokenError("ECDSA JWS signature length is invalid")
            digest = {"ES256": hashes.SHA256, "ES384": hashes.SHA384, "ES512": hashes.SHA512}[alg]()
            der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
            _public_key(jwk).verify(der, signed, ec.ECDSA(digest)); verified = True
        elif alg == "EdDSA":
            _public_key(jwk).verify(signature, signed); verified = True
        else:
            raise TokenError("JWS alg/key type combination is unsupported")
    except TokenError:
        raise
    except Exception:
        verified = False
    payload_json = None
    if verified:
        try:
            payload_json = json.loads(parsed["payload"])
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return {"verified": verified, "protected": header,
            "payload": parsed["payload"] if verified else None,
            "payload_json": payload_json, "thumbprint": _jwk_material(jwk),
            "offline": True, "requests_sent": 0}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise TokenError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="token_depth.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    inspect = sub.add_parser("inspect"); inspect.add_argument("token")
    jwks = sub.add_parser("jwks"); jwks.add_argument("input")
    verify = sub.add_parser("verify"); verify.add_argument("token"); verify.add_argument("jwk")
    decrypt = sub.add_parser("decrypt"); decrypt.add_argument("token")
    key = decrypt.add_mutually_exclusive_group(required=True)
    key.add_argument("--key-hex"); key.add_argument("--key-file")
    for command in (inspect, jwks, verify, decrypt):
        command.add_argument("--json", action="store_true")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.operation == "inspect":
            result = parse_compact(args.token)
        elif args.operation == "jwks":
            path = Path(args.input)
            if not path.is_file() or path.stat().st_size > MAX_JSON:
                raise TokenError("JWKS is absent or over cap")
            result = assess_jwks(json.loads(path.read_text("utf-8"), object_pairs_hook=_pairs))
        elif args.operation == "verify":
            path = Path(args.jwk)
            if not path.is_file() or path.stat().st_size > MAX_JSON:
                raise TokenError("JWK is absent or over cap")
            result = verify_jws(args.token, json.loads(path.read_text("utf-8"), object_pairs_hook=_pairs))
        else:
            key_material = bytes.fromhex(args.key_hex) if args.key_hex else Path(args.key_file).read_bytes()
            result = decrypt_jwe(args.token, key_material)
        print(json.dumps(result, sort_keys=True, default=lambda value: {"hex": value.hex()} if isinstance(value, bytes) else str(value),
                         indent=2 if args.json else None))
        return 0
    except Exception as exc:
        print(f"token_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
