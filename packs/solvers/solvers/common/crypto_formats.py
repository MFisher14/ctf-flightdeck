"""Bounded, offline cryptographic-format structure analyzers.

The analyzers never fetch URLs/keyservers, open sockets, execute data, or expose
private key material.  Reports are frozen dataclasses containing structure and
public metadata only.  Parsing is capped by byte/item/depth limits and malformed
or ambiguous input returns ``None``.  The sole secret recovery helper is a
bounded JWT HMAC dictionary check and returns a key only after exact signature
re-verification and uniqueness.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import struct
from dataclasses import dataclass
from datetime import UTC
from typing import Iterable, Optional


MAX_BYTES = 2 << 20
MAX_PACKETS = 256
MAX_ITEMS = 4096
MAX_CANDIDATES = 1 << 16
MAX_JSON_DEPTH = 16
MAX_KEY_BYTES = 2048

__all__ = [
    "CryptoConfigReport", "JWKReport", "JWTReport", "PGPPacket", "PGPReport",
    "SSHReport", "TLSCertificate", "TLSReport", "analyze_age_sops", "analyze_jwk",
    "analyze_jwt", "analyze_pgp", "analyze_ssh", "analyze_tls",
    "recover_jwt_hmac_secret",
]


@dataclass(frozen=True)
class PGPPacket:
    tag: int
    length: int
    version: Optional[int]
    algorithm: Optional[int]
    s2k_type: Optional[int]
    s2k_hash: Optional[int]
    s2k_count: Optional[int]


@dataclass(frozen=True)
class PGPReport:
    armored: bool
    armor_type: Optional[str]
    crc24_valid: Optional[bool]
    packets: tuple[PGPPacket, ...]
    public_fingerprints: tuple[str, ...]
    user_ids: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class SSHReport:
    format: str
    key_type: Optional[str]
    bits: Optional[int]
    fingerprint_sha256: Optional[str]
    fingerprint_md5: Optional[str]
    comment: Optional[str]
    encrypted: bool
    cipher: Optional[str]
    kdf: Optional[str]
    public_fields: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class TLSCertificate:
    subject: str
    issuer: str
    serial: int
    key_type: str
    key_bits: Optional[int]
    signature_hash: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]


@dataclass(frozen=True)
class TLSReport:
    record_versions: tuple[str, ...]
    handshake_types: tuple[int, ...]
    cipher_suites: tuple[str, ...]
    selected_cipher: Optional[str]
    supported_versions: tuple[str, ...]
    groups: tuple[str, ...]
    certificates: tuple[TLSCertificate, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class CryptoConfigReport:
    kind: str
    recipients: tuple[str, ...]
    kdfs: tuple[str, ...]
    nonces: tuple[str, ...]
    algorithms: tuple[str, ...]
    mac_present: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class JWTReport:
    algorithm: Optional[str]
    key_id: Optional[str]
    jku: Optional[str]
    jwk_kty: Optional[str]
    header_json: str
    payload_json: str
    signature_bytes: int
    signed: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class JWKReport:
    kty: str
    kid: Optional[str]
    algorithm: Optional[str]
    use: Optional[str]
    key_bits: Optional[int]
    curve: Optional[str]
    has_private: bool
    thumbprint_sha256: Optional[str]
    warnings: tuple[str, ...]


def _ints(*values: object) -> bool:
    return all(isinstance(v, int) and not isinstance(v, bool) for v in values)


def _bounded(values: object, cap: int = MAX_ITEMS) -> Optional[list[object]]:
    try:
        import itertools
        result = list(itertools.islice(iter(values), cap + 1))
    except Exception:
        return None
    return result if len(result) <= cap else None


def _bytes(value: object) -> Optional[bytes]:
    if type(value) is str:
        if len(value) > MAX_BYTES:
            return None
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError:
            return None
        return encoded if len(encoded) <= MAX_BYTES else None
    if type(value) in (bytes, bytearray) and len(value) <= MAX_BYTES:
        return bytes(value)
    return None


def _b64u_decode(value: str, cap: int = MAX_BYTES) -> Optional[bytes]:
    if type(value) is not str or not _ints(cap) or cap < 0 or len(value) > cap * 2 \
            or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        return None
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    canonical = base64.urlsafe_b64encode(result).decode("ascii").rstrip("=")
    return result if len(result) <= cap and hmac.compare_digest(canonical, value) else None


def _canonical_b64(value: str, *, exact_bytes: Optional[int] = None) -> bool:
    if type(value) is not str or not value or not re.fullmatch(r"[A-Za-z0-9+/]+", value):
        return False
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except (binascii.Error, ValueError):
        return False
    canonical = base64.b64encode(decoded).decode("ascii").rstrip("=")
    return bool(decoded) and canonical == value and (exact_bytes is None or len(decoded) == exact_bytes)


def _json_structure_bounded(value: object, cap: int) -> bool:
    """Validate JSON-shaped caller data with iterative depth/item/byte caps."""
    stack = [(value, 0)]
    items = text_bytes = 0
    while stack:
        node, depth = stack.pop()
        items += 1
        if items > MAX_ITEMS or depth > MAX_JSON_DEPTH:
            return False
        if type(node) is dict:
            for key, child in node.items():
                if type(key) is not str:
                    return False
                try:
                    text_bytes += len(key.encode("utf-8"))
                except UnicodeEncodeError:
                    return False
                stack.append((child, depth + 1))
        elif type(node) is list:
            stack.extend((child, depth + 1) for child in node)
        elif type(node) is str:
            try:
                text_bytes += len(node.encode("utf-8"))
            except UnicodeEncodeError:
                return False
        elif node is None or type(node) is bool:
            pass
        elif type(node) is int:
            if abs(node).bit_length() > cap * 8:
                return False
        elif type(node) is float:
            if not math.isfinite(node):
                return False
        else:
            return False
        if text_bytes > cap:
            return False
    return True


def _json_object(raw: bytes, cap: int) -> Optional[dict]:
    if not _ints(cap) or cap < 0 or len(raw) > cap:
        return None

    pair_count = 0

    def hook(pairs):
        nonlocal pair_count
        pair_count += len(pairs)
        if pair_count > MAX_ITEMS:
            raise ValueError("JSON item cap")
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=hook,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None
    return value if type(value) is dict and _json_structure_bounded(value, cap) else None


# ---- OpenPGP --------------------------------------------------------------------------------------

def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _dearmor(data: bytes) -> Optional[tuple[bytes, str, Optional[bool]]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    match = re.fullmatch(
        r"\s*-----BEGIN PGP ([A-Z ]+)-----\r?\n(.*?)-----END PGP \1-----\s*",
        text,
        re.S,
    )
    if not match:
        return None
    lines = match.group(2).splitlines()
    body_started, encoded, checksum = False, [], None
    for line in lines:
        line = line.strip()
        if not body_started and ":" in line:
            continue
        if not line:
            body_started = True
            continue
        body_started = True
        if line.startswith("="):
            if checksum is not None:
                return None
            checksum = line[1:]
        elif checksum is None:
            encoded.append(line)
        else:
            return None
    try:
        blob = base64.b64decode("".join(encoded), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(blob) > MAX_BYTES:
        return None
    valid = None
    if checksum is not None:
        try:
            check = base64.b64decode(checksum, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(check) != 3:
            return None
        valid = int.from_bytes(check, "big") == _crc24(blob)
    return blob, match.group(1), valid


def _pgp_length(data: bytes, offset: int, new: bool, length_type: int = 0) -> Optional[tuple[int, int]]:
    if new:
        if offset >= len(data):
            return None
        first = data[offset]
        if first < 192:
            return first, offset + 1
        if first < 224 and offset + 1 < len(data):
            return ((first - 192) << 8) + data[offset + 1] + 192, offset + 2
        if first == 255 and offset + 4 < len(data):
            return int.from_bytes(data[offset + 1:offset + 5], "big"), offset + 5
        return None  # Partial body lengths deliberately unsupported.
    size = (1, 2, 4)[length_type] if length_type < 3 else 0
    if not size or offset + size > len(data):
        return None
    return int.from_bytes(data[offset:offset + size], "big"), offset + size


def _pgp_mpis_end(body: bytes, offset: int, count: int) -> Optional[int]:
    """Return the byte after canonical OpenPGP MPIs, or fail closed."""
    for _ in range(count):
        if offset + 2 > len(body):
            return None
        bits = int.from_bytes(body[offset:offset + 2], "big")
        size = (bits + 7) // 8
        offset += 2
        if not bits or offset + size > len(body):
            return None
        value = body[offset:offset + size]
        if not value or int.from_bytes(value, "big").bit_length() != bits:
            return None
        offset += size
    return offset


def _pgp_ecc_end(body: bytes, offset: int, algorithm: int) -> Optional[int]:
    if offset >= len(body):
        return None
    oid_length = body[offset]
    offset += 1
    if not (1 <= oid_length <= 32) or offset + oid_length > len(body):
        return None
    offset += oid_length
    offset = _pgp_mpis_end(body, offset, 1)
    if offset is None:
        return None
    if algorithm != 18:
        return offset
    if offset >= len(body):
        return None
    kdf_length = body[offset]
    if kdf_length < 3 or offset + 1 + kdf_length > len(body):
        return None
    return offset + 1 + kdf_length


def analyze_pgp(value: object) -> Optional[PGPReport]:
    data = _bytes(value)
    if not data or len(data) > MAX_BYTES:
        return None
    armored, armor_type, crc_valid = False, None, None
    if data.lstrip().startswith(b"-----BEGIN PGP "):
        decoded = _dearmor(data)
        if decoded is None:
            return None
        data, armor_type, crc_valid = decoded
        armored = True
        if not data:
            return None
    packets, fingerprints, user_ids, warnings = [], [], [], []
    offset = 0
    while offset < len(data):
        if len(packets) >= MAX_PACKETS:
            return None
        header = data[offset]
        if not header & 0x80:
            return None
        offset += 1
        new = bool(header & 0x40)
        tag = header & 0x3F if new else (header >> 2) & 0x0F
        if tag == 0:
            return None
        parsed = _pgp_length(data, offset, new, header & 0x03)
        if parsed is None:
            return None
        length, offset = parsed
        if length > MAX_BYTES or offset + length > len(data):
            return None
        body = data[offset:offset + length]
        offset += length
        version = body[0] if body else None
        algorithm = None
        s2k_type = s2k_hash = s2k_count = None
        if tag in (6, 14):
            if len(body) < 6:
                return None
            if version not in (3, 4):
                return None
            if version == 3:
                if len(body) < 8:
                    return None
                algorithm = body[7]
                if algorithm not in (1, 2, 3):
                    return None
                mpi_end = _pgp_mpis_end(body, 8, 2)
            else:
                algorithm = body[5]
                mpi_counts = {1: 2, 2: 2, 3: 2, 16: 3, 17: 4, 20: 3}
                if algorithm in mpi_counts:
                    mpi_end = _pgp_mpis_end(body, 6, mpi_counts[algorithm])
                elif algorithm in (18, 19, 22):
                    mpi_end = _pgp_ecc_end(body, 6, algorithm)
                else:
                    return None
            if mpi_end != len(body):
                return None
            if version == 4 and len(body) < 65536:
                fingerprint = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest()
                fingerprints.append(fingerprint)
        elif tag == 13:
            try:
                user_ids.append(body.decode("utf-8"))
            except UnicodeDecodeError:
                warnings.append("non_utf8_user_id")
        elif tag == 3:
            if len(body) < 4:
                return None
            if version != 4:
                return None
            algorithm = body[1]
            s2k_type, s2k_hash = body[2], body[3]
            cursor = 4
            if s2k_type in (1, 3):
                if len(body) < cursor + 8:
                    return None
                cursor += 8
            if s2k_type == 3:
                if cursor >= len(body):
                    return None
                encoded = body[cursor]
                s2k_count = (16 + (encoded & 15)) << ((encoded >> 4) + 6)
            elif s2k_type not in (0, 1, 3):
                warnings.append("unknown_s2k")
        packets.append(PGPPacket(tag, length, version, algorithm, s2k_type, s2k_hash, s2k_count))
    if crc_valid is False:
        warnings.append("armor_crc24_mismatch")
    return PGPReport(armored, armor_type, crc_valid, tuple(packets), tuple(fingerprints),
                     tuple(user_ids), tuple(sorted(set(warnings))))


# ---- SSH ------------------------------------------------------------------------------------------

_SSH_TYPES = {"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-nistp256",
              "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
_OPENSSH_CIPHER_BLOCKS = {
    "3des-cbc": 8,
    "aes128-cbc": 16, "aes192-cbc": 16, "aes256-cbc": 16,
    "aes128-ctr": 16, "aes192-ctr": 16, "aes256-ctr": 16,
    "aes128-gcm@openssh.com": 16, "aes256-gcm@openssh.com": 16,
    "chacha20-poly1305@openssh.com": 8,
}


def _ssh_fields(blob: bytes, cap: int = 64) -> Optional[tuple[bytes, ...]]:
    fields, offset = [], 0
    while offset < len(blob):
        if len(fields) >= cap or offset + 4 > len(blob):
            return None
        length = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        if length > MAX_BYTES or offset + length > len(blob):
            return None
        fields.append(blob[offset:offset + length])
        offset += length
    return tuple(fields)


def _ssh_string(blob: bytes, offset: int, cap: int = MAX_BYTES) -> Optional[tuple[bytes, int]]:
    if offset + 4 > len(blob):
        return None
    length = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if length > cap or offset + length > len(blob):
        return None
    return blob[offset:offset + length], offset + length


def _fingerprints(blob: bytes) -> tuple[str, str]:
    sha = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    md5 = "MD5:" + ":".join(f"{byte:02x}" for byte in hashlib.md5(blob).digest())
    return sha, md5


def _ssh_public_report(line: str) -> Optional[SSHReport]:
    parts = line.strip().split()
    key_index = next((i for i, part in enumerate(parts) if part in _SSH_TYPES), None)
    if key_index is None or key_index + 1 >= len(parts):
        return None
    key_type = parts[key_index]
    try:
        blob = base64.b64decode(parts[key_index + 1], validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(blob) > MAX_BYTES:
        return None
    fields = _ssh_fields(blob)
    if not fields or fields[0].decode("ascii", "replace") != key_type:
        return None
    bits = None
    if key_type == "ssh-rsa" and len(fields) == 3:
        if not fields[1] or not fields[2]:
            return None
        bits = int.from_bytes(fields[2], "big").bit_length()
    elif key_type == "ssh-ed25519" and len(fields) == 2 and len(fields[1]) == 32:
        bits = 256
    elif key_type == "ssh-ed25519":
        return None
    elif key_type.startswith("ecdsa-sha2-nistp"):
        if len(fields) != 3 or fields[1].decode("ascii", "replace") not in key_type:
            return None
        bits = int(key_type.rsplit("nistp", 1)[-1])
    elif key_type == "ssh-dss" and len(fields) != 5:
        return None
    elif key_type == "ssh-rsa":
        return None
    warnings = []
    try:
        from cryptography.hazmat.primitives import serialization
        loaded = serialization.load_ssh_public_key((key_type + " " + parts[key_index + 1]).encode())
        if getattr(loaded, "key_size", bits) != bits:
            warnings.append("library_bit_mismatch")
    except Exception:
        return None
    sha, md5 = _fingerprints(blob)
    comment = " ".join(parts[key_index + 2:]) or None
    public_fields = tuple(field.hex() for field in fields[1:])
    return SSHReport("authorized_key", key_type, bits, sha, md5, comment, False, None, None,
                     public_fields, tuple(warnings))


def _private_public_metadata(key) -> tuple[Optional[str], Optional[int], Optional[bytes]]:
    try:
        from cryptography.hazmat.primitives import serialization
        public = key.public_key()
        key_type = type(public).__name__.replace("PublicKey", "").lower()
        bits = getattr(public, "key_size", 256 if "ed25519" in key_type else None)
        wire = public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        blob = base64.b64decode(wire.split()[1], validate=True)
        return key_type, bits, blob
    except Exception:
        return None, None, None


def analyze_ssh(value: object, *, password: Optional[bytes] = None) -> Optional[SSHReport]:
    data = _bytes(value)
    if not data or (password is not None and (type(password) is not bytes or len(password) > 4096)):
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    for line in text.splitlines():
        public = _ssh_public_report(line)
        if public is not None:
            return public
    label = re.search(br"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----", data)
    if not label:
        return None
    encrypted = b"ENCRYPTED" in label.group(1) or b"Proc-Type: 4,ENCRYPTED" in data
    cipher = kdf = None
    openssh_container_valid = False
    if b"BEGIN OPENSSH PRIVATE KEY" in data:
        match = re.search(br"-----BEGIN OPENSSH PRIVATE KEY-----\s*(.*?)\s*-----END OPENSSH PRIVATE KEY-----", data, re.S)
        if not match:
            return None
        try:
            blob = base64.b64decode(re.sub(br"\s", b"", match.group(1)), validate=True)
        except (binascii.Error, ValueError):
            return None
        if not blob.startswith(b"openssh-key-v1\0"):
            return None
        cursor = len(b"openssh-key-v1\0")
        parsed = _ssh_string(blob, cursor, 64)
        if parsed is None:
            return None
        cipher_raw, cursor = parsed
        parsed = _ssh_string(blob, cursor, 64)
        if parsed is None:
            return None
        kdf_raw, cursor = parsed
        parsed = _ssh_string(blob, cursor, 4096)
        if parsed is None:
            return None
        kdf_options, cursor = parsed
        try:
            cipher = cipher_raw.decode("ascii")
            kdf = kdf_raw.decode("ascii")
        except UnicodeDecodeError:
            return None
        if cursor + 4 > len(blob):
            return None
        key_count = int.from_bytes(blob[cursor:cursor + 4], "big")
        cursor += 4
        if not (1 <= key_count <= 64):
            return None
        for _ in range(key_count):
            parsed = _ssh_string(blob, cursor)
            if parsed is None:
                return None
            public_blob, cursor = parsed
            public_fields = _ssh_fields(public_blob)
            if not public_fields:
                return None
            try:
                public_type = public_fields[0].decode("ascii")
            except UnicodeDecodeError:
                return None
            public_line = public_type + " " + base64.b64encode(public_blob).decode("ascii")
            if _ssh_public_report(public_line) is None:
                return None
        parsed = _ssh_string(blob, cursor)
        if parsed is None:
            return None
        private_block, cursor = parsed
        if not private_block or cursor != len(blob):
            return None
        encrypted = cipher != "none"
        if ((not encrypted and (kdf != "none" or kdf_options))
                or (encrypted and (not cipher or kdf in ("", "none") or not kdf_options))):
            return None
        if encrypted:
            block_size = _OPENSSH_CIPHER_BLOCKS.get(cipher)
            if block_size is None or kdf != "bcrypt":
                return None
            kdf_parsed = _ssh_string(kdf_options, 0, 64)
            if kdf_parsed is None:
                return None
            salt, kdf_cursor = kdf_parsed
            if not (16 <= len(salt) <= 64) or kdf_cursor + 4 != len(kdf_options):
                return None
            rounds = int.from_bytes(kdf_options[kdf_cursor:kdf_cursor + 4], "big")
            if not (1 <= rounds <= 1_000_000):
                return None
            if len(private_block) < block_size or len(private_block) % block_size:
                return None
        openssh_container_valid = True
    try:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_ssh_private_key(data, password=password) if b"OPENSSH" in label.group(1) \
            else serialization.load_pem_private_key(data, password=password)
    except TypeError:
        if password is not None or not encrypted:
            return None
        if b"OPENSSH" in label.group(1) and not openssh_container_valid:
            return None
        return SSHReport("private_key", None, None, None, None, None, True, cipher, kdf, (),
                         ("private_key_not_loaded",))
    except Exception:
        return None
    key_type, bits, blob = _private_public_metadata(key)
    sha = md5 = None
    if blob is not None:
        sha, md5 = _fingerprints(blob)
    return SSHReport("private_key", key_type, bits, sha, md5, None, encrypted, cipher, kdf, (), ())


# ---- TLS ------------------------------------------------------------------------------------------

_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
_TLS_CONTENT_TYPES = {20, 21, 22, 23, 24}
_CIPHERS = {0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
_GROUPS = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
           256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096"}


def _version(value: int) -> str:
    return _VERSIONS.get(value, f"0x{value:04x}")


def _cipher(value: int) -> str:
    return _CIPHERS.get(value, f"0x{value:04x}")


def _group(value: int) -> str:
    return _GROUPS.get(value, f"0x{value:04x}")


def _certificate(der: bytes) -> Optional[TLSCertificate]:
    if not der or len(der) > MAX_BYTES:
        return None
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        public = cert.public_key()
        key_type = type(public).__name__.replace("PublicKey", "").lower()
        bits = getattr(public, "key_size", 256 if "ed25519" in key_type else None)
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=UTC)).isoformat()
        after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=UTC)).isoformat()
        return TLSCertificate(cert.subject.rfc4514_string(), cert.issuer.rfc4514_string(), cert.serial_number,
                              key_type, bits, sig_hash, before, after)
    except Exception:
        return None


def _extensions(data: bytes, hello_kind: int) -> Optional[tuple[tuple[str, ...], tuple[str, ...]]]:
    versions, groups = [], []
    offset = count = 0
    seen = set()
    while offset < len(data):
        count += 1
        if count > MAX_ITEMS:
            return None
        if offset + 4 > len(data):
            return None
        kind, length = int.from_bytes(data[offset:offset + 2], "big"), int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4
        if kind in seen:
            return None
        seen.add(kind)
        if offset + length > len(data):
            return None
        body = data[offset:offset + length]
        offset += length
        if kind == 10:
            if len(body) < 4 or int.from_bytes(body[:2], "big") != len(body) - 2 or (len(body) - 2) % 2:
                return None
            groups.extend(_group(int.from_bytes(body[i:i + 2], "big")) for i in range(2, len(body), 2))
        elif kind == 43:
            if hello_kind == 2 and len(body) == 2:
                values = body
            elif (hello_kind == 1 and len(body) >= 3 and body[0] == len(body) - 1
                  and (len(body) - 1) % 2 == 0):
                values = body[1:]
            else:
                return None
            version_numbers = [int.from_bytes(values[i:i + 2], "big") for i in range(0, len(values), 2)]
            if any(value not in _VERSIONS for value in version_numbers):
                return None
            versions.extend(_version(value) for value in version_numbers)
    return tuple(versions), tuple(groups)


def _parse_hello(kind: int, body: bytes):
    if len(body) < 35:
        return None
    legacy_number = int.from_bytes(body[:2], "big")
    if legacy_number not in _VERSIONS:
        return None
    legacy = _version(legacy_number)
    offset = 34
    sid_len = body[offset]
    offset += 1
    if offset + sid_len > len(body):
        return None
    offset += sid_len
    if kind == 1:
        if offset + 2 > len(body):
            return None
        clen = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if clen < 2 or clen % 2 or offset + clen > len(body):
            return None
        ciphers = tuple(_cipher(int.from_bytes(body[i:i + 2], "big")) for i in range(offset, offset + clen, 2))
        offset += clen
        if offset >= len(body):
            return None
        comp_len = body[offset]
        if comp_len < 1 or offset + 1 + comp_len > len(body) or 0 not in body[offset + 1:offset + 1 + comp_len]:
            return None
        offset += 1 + comp_len
        selected = None
    else:
        if offset + 3 > len(body):
            return None
        selected = _cipher(int.from_bytes(body[offset:offset + 2], "big"))
        ciphers = (selected,)
        if body[offset + 2] != 0:
            return None
        offset += 3
    versions = groups = ()
    if offset + 2 <= len(body):
        ext_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if offset + ext_len != len(body):
            return None
        parsed_extensions = _extensions(body[offset:], kind)
        if parsed_extensions is None:
            return None
        versions, groups = parsed_extensions
    elif offset != len(body):
        return None
    return legacy, ciphers, selected, versions, groups


def analyze_tls(value: object) -> Optional[TLSReport]:
    if type(value) is dict:
        if len(value) > 64:
            return None
        selected_raw = value.get("cipher")
        versions_raw = value.get("versions", [value.get("version")] if value.get("version") is not None else [])
        ciphers_raw = value.get("cipher_suites", [selected_raw] if selected_raw is not None else [])
        groups_raw = value.get("groups", [])
        certs_raw = value.get("certificates", [])
        if not all(type(rows) in (list, tuple) for rows in (versions_raw, ciphers_raw, groups_raw, certs_raw)):
            return None
        if len(versions_raw) > 256 or len(ciphers_raw) > 256 or len(groups_raw) > 256 or len(certs_raw) > 64:
            return None
        if any(type(item) not in (str, int)
               for rows in (versions_raw, ciphers_raw, groups_raw) for item in rows):
            return None
        if selected_raw is not None and type(selected_raw) not in (str, int):
            return None
        if any(type(item) is str and not item
               for rows in (versions_raw, ciphers_raw, groups_raw) for item in rows):
            return None
        if type(selected_raw) is str and not selected_raw:
            return None
        if any(type(item) is int and not (0 <= item <= 0xFFFF)
               for rows in (versions_raw, ciphers_raw, groups_raw) for item in rows):
            return None
        if any((type(item) is int and item not in _VERSIONS)
               or (type(item) is str and item not in _VERSIONS.values()) for item in versions_raw):
            return None
        if type(selected_raw) is int and not (0 <= selected_raw <= 0xFFFF):
            return None
        if any(type(raw) not in (bytes, bytearray) or len(raw) > MAX_BYTES for raw in certs_raw):
            return None
        try:
            total_bytes = sum(len(item.encode("utf-8")) if type(item) is str else 2
                              for rows in (versions_raw, ciphers_raw, groups_raw) for item in rows)
        except UnicodeEncodeError:
            return None
        if total_bytes + sum(len(raw) for raw in certs_raw) > MAX_BYTES:
            return None
        versions = tuple(item if type(item) is str else _version(item) for item in versions_raw)
        ciphers = tuple(item if type(item) is str else _cipher(item) for item in ciphers_raw)
        groups = tuple(item if type(item) is str else _group(item) for item in groups_raw)
        certificates = tuple(_certificate(bytes(raw)) for raw in certs_raw)
        if any(cert is None for cert in certificates):
            return None
        selected = selected_raw if type(selected_raw) is str else (_cipher(selected_raw) if type(selected_raw) is int else None)
        if selected is not None and selected not in ciphers:
            return None
        if not (versions or ciphers or groups or certificates):
            return None
        return TLSReport(versions, (), ciphers, selected,
                         versions, groups, certificates, ())
    data = _bytes(value)
    if not data:
        return None
    record_versions, handshake_types, ciphers, supported, groups, certificates, warnings = [], [], [], [], [], [], []
    handshake_parts = []
    offset, records, selected_cipher = 0, 0, None
    client_offered = set()
    handshake_bytes = 0
    while offset < len(data):
        records += 1
        if records > 256 or offset + 5 > len(data):
            return None
        content_type, version, length = data[offset], int.from_bytes(data[offset + 1:offset + 3], "big"), int.from_bytes(data[offset + 3:offset + 5], "big")
        offset += 5
        if content_type not in _TLS_CONTENT_TYPES or version not in _VERSIONS:
            return None
        if length > (1 << 14) + 2048 or offset + length > len(data):
            return None
        record_versions.append(_version(version))
        body = data[offset:offset + length]
        offset += length
        if content_type == 22:
            handshake_bytes += len(body)
            if handshake_bytes > MAX_BYTES:
                return None
            handshake_parts.append(body)
    handshake_stream = b"".join(handshake_parts)
    cursor = 0
    while cursor < len(handshake_stream):
        if cursor + 4 > len(handshake_stream):
            return None
        kind, hlen = handshake_stream[cursor], int.from_bytes(handshake_stream[cursor + 1:cursor + 4], "big")
        cursor += 4
        if hlen > MAX_BYTES or cursor + hlen > len(handshake_stream):
            return None
        message = handshake_stream[cursor:cursor + hlen]
        cursor += hlen
        if len(handshake_types) >= MAX_ITEMS:
            return None
        handshake_types.append(kind)
        if kind in (1, 2):
            hello = _parse_hello(kind, message)
            if hello is None:
                return None
            _, offered, selected, versions, named_groups = hello
            ciphers.extend(offered)
            if kind == 1:
                client_offered.update(offered)
            if kind == 2:
                if selected_cipher is not None and selected_cipher != selected:
                    return None
                if client_offered and selected not in client_offered:
                    return None
                selected_cipher = selected
            supported.extend(versions)
            groups.extend(named_groups)
        elif kind == 11:
            if len(message) < 3:
                return None
            total = int.from_bytes(message[:3], "big")
            if not total or total != len(message) - 3:
                return None
            pos = 3
            cert_count = 0
            while pos < len(message):
                cert_count += 1
                if cert_count > 256:
                    return None
                if pos + 3 > len(message):
                    return None
                size = int.from_bytes(message[pos:pos + 3], "big")
                pos += 3
                if not size or size > MAX_BYTES or pos + size > len(message):
                    return None
                cert = _certificate(message[pos:pos + size])
                if cert is None:
                    warnings.append("unparsed_certificate")
                else:
                    certificates.append(cert)
                pos += size
    if client_offered and selected_cipher is not None and selected_cipher not in client_offered:
        return None
    return TLSReport(tuple(record_versions), tuple(handshake_types), tuple(dict.fromkeys(ciphers)), selected_cipher,
                     tuple(dict.fromkeys(supported)), tuple(dict.fromkeys(groups)), tuple(certificates),
                     tuple(sorted(set(warnings))))


# ---- age / sops -----------------------------------------------------------------------------------

_ENC_FIELD = re.compile(r"ENC\[[^\]]*?\biv:([^,\]]+)[^\]]*\]", re.I)


def _walk_json(value, *, depth=0, budget=None):
    if budget is None:
        budget = [MAX_ITEMS]
    if depth > 16 or budget[0] <= 0:
        raise ValueError("JSON structure cap")
    budget[0] -= 1
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_json(child, depth=depth + 1, budget=budget)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child, depth=depth + 1, budget=budget)


def analyze_age_sops(value: object) -> Optional[CryptoConfigReport]:
    data = _bytes(value)
    if not data:
        return None
    text = data.decode("utf-8", "replace")
    recipients, kdfs, nonces, algorithms, warnings = set(), set(), set(), set(), set()
    mac_present, kind = False, None
    if text.startswith("age-encryption.org/"):
        lines = text.splitlines()
        if not lines or lines[0] != "age-encryption.org/v1":
            return None
        kind = "age"
        stanza_count = 0
        stanza_has_body = False
        delimiter_seen = False
        for index, line in enumerate(lines[1:], 1):
            if line.startswith("-> "):
                if stanza_count and not stanza_has_body:
                    return None
                stanza_count += 1
                if stanza_count > MAX_ITEMS:
                    return None
                parts = line[3:].split()
                if len(parts) < 2:
                    return None
                algorithms.add(parts[0])
                if parts[0] == "scrypt":
                    kdfs.add("scrypt:" + ":".join(parts[1:]))
                else:
                    recipients.add(parts[1])
                stanza_has_body = False
            elif line.startswith("--- "):
                mac = line[4:]
                payload = [part for part in lines[index + 1:] if part]
                if (delimiter_seen or not stanza_count or not stanza_has_body or not mac
                        or not _canonical_b64(mac, exact_bytes=32)
                        or not payload or not all(_canonical_b64(part) for part in payload)):
                    return None
                delimiter_seen = True
                mac_present = True
                break
            elif stanza_count and line and _canonical_b64(line):
                stanza_has_body = True
            elif line:
                return None
        if not delimiter_seen:
            return None
    else:
        document = _json_object(data, MAX_BYTES)
        if text.lstrip().startswith(("{", "[")) and document is None:
            return None
        if isinstance(document, dict) and isinstance(document.get("sops"), dict):
            kind = "sops"
            sops = document["sops"]
            try:
                nodes = list(_walk_json(document))
            except (ValueError, RecursionError):
                return None
            age_entries = sops.get("age", [])
            if not isinstance(age_entries, list):
                return None
            for entry in age_entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("recipient"), str):
                    return None
                recipients.add(entry["recipient"])
                algorithms.add("age")
            for name in ("pgp", "kms", "gcp_kms", "azure_kv", "hc_vault", "key_groups"):
                if sops.get(name):
                    algorithms.add(name)
            if _ints(sops.get("shamir_threshold")):
                kdfs.add(f"shamir_threshold:{sops['shamir_threshold']}")
            mac = sops.get("mac")
            if type(mac) is not str or not re.fullmatch(r"ENC\[[^\]]+\]", mac):
                return None
            mac_present = True
            for node in nodes:
                if isinstance(node, str):
                    nonces.update(_ENC_FIELD.findall(node))
        else:
            # Bounded structural YAML/text fallback: metadata only, never values.
            if len(text) > MAX_BYTES:
                return None
            if re.search(r"(?m)^sops:\s*$", text):
                kind = "sops"
                recipients.update(re.findall(r"(?m)^\s*(?:-\s*)?recipient:\s*([^\s#]+)", text))
                nonces.update(_ENC_FIELD.findall(text))
                mac_present = bool(re.search(r"(?m)^\s*mac:\s*ENC\[[^\]\r\n]+\]\s*(?:#.*)?$", text))
                algorithms.update(name for name in ("age", "pgp", "kms") if re.search(rf"(?m)^\s*{name}:\s*", text))
    if kind is None:
        return None
    if kind == "sops" and not mac_present:
        return None
    if sum(len(items) for items in (recipients, kdfs, nonces, algorithms)) > MAX_ITEMS:
        return None
    if sum(len(item.encode("utf-8")) for items in (recipients, kdfs, nonces, algorithms) for item in items) > MAX_BYTES:
        return None
    return CryptoConfigReport(kind, tuple(sorted(recipients)), tuple(sorted(kdfs)), tuple(sorted(nonces)),
                              tuple(sorted(algorithms)), mac_present, tuple(sorted(warnings)))


# ---- JWT / JWK ------------------------------------------------------------------------------------

def analyze_jwt(token: object) -> Optional[JWTReport]:
    if type(token) is not str or len(token) > MAX_BYTES:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_raw, payload_raw, signature = _b64u_decode(parts[0], 16_384), _b64u_decode(parts[1], 131_072), _b64u_decode(parts[2], 16_384)
    if header_raw is None or payload_raw is None or signature is None:
        return None
    header, payload = _json_object(header_raw, 16_384), _json_object(payload_raw, 131_072)
    if header is None or payload is None:
        return None
    alg = header.get("alg") if type(header.get("alg")) is str else None
    kid = header.get("kid") if type(header.get("kid")) is str else None
    jku = header.get("jku") if type(header.get("jku")) is str else None
    jwk = header.get("jwk")
    jwk_kty = jwk.get("kty") if type(jwk) is dict and type(jwk.get("kty")) is str else None
    warnings = []
    if alg is None:
        warnings.append("missing_alg")
    elif alg.lower() == "none":
        warnings.append("alg_none")
    if jku:
        warnings.append("external_jku_not_fetched")
    if jwk_kty:
        warnings.append("embedded_jwk")
    try:
        header_json = json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        return None
    return JWTReport(alg, kid, jku, jwk_kty, header_json, payload_json, len(signature), bool(signature), tuple(warnings))


def recover_jwt_hmac_secret(token: object, candidates: Iterable[bytes], *, max_candidates: int = MAX_CANDIDATES) -> Optional[bytes]:
    if type(max_candidates) is not int or not (1 <= max_candidates <= MAX_CANDIDATES):
        return None
    report = analyze_jwt(token)
    values = _bounded(candidates, max_candidates)
    if report is None or values is None or type(token) is not str:
        return None
    algorithms = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    digest = algorithms.get(report.algorithm)
    if digest is None:
        return None
    parts = token.split(".")
    signature = _b64u_decode(parts[2], digest().digest_size)
    if signature is None:
        return None
    if any(type(candidate) is not bytes or not candidate or len(candidate) > 4096 for candidate in values):
        return None
    if sum(len(candidate) for candidate in values) + len(token) > MAX_BYTES:
        return None
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    found = set()
    for candidate in values:
        expected = hmac.new(candidate, signing_input, digest).digest()
        if hmac.compare_digest(expected, signature):
            found.add(candidate)
    if len(found) != 1:
        return None
    secret = next(iter(found))
    return secret if hmac.compare_digest(hmac.new(secret, signing_input, digest).digest(), signature) else None


def analyze_jwk(value: object) -> Optional[JWKReport]:
    if type(value) is str:
        raw = _bytes(value)
        document = _json_object(raw, MAX_BYTES) if raw else None
    elif type(value) is dict:
        if len(value) > 64:
            return None
        document = value
    else:
        return None
    if type(document) is not dict or not _json_structure_bounded(document, MAX_BYTES):
        return None
    if "keys" in document:
        keys = document.get("keys")
        if type(keys) is not list or len(keys) != 1 or type(keys[0]) is not dict:
            return None
        document = keys[0]
    if len(document) > 64:
        return None
    kty = document.get("kty")
    if type(kty) is not str:
        return None
    private_names = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    has_private = any(name in document for name in private_names)
    if kty in {"RSA", "EC", "OKP"} and has_private:
        return None
    bits, curve, warnings, thumbprint = None, document.get("crv") if type(document.get("crv")) is str else None, [], None
    canonical = None
    if kty == "RSA" and type(document.get("n")) is str and type(document.get("e")) is str:
        nraw, eraw = _b64u_decode(document["n"], MAX_KEY_BYTES), _b64u_decode(document["e"], 32)
        if not nraw or not eraw or (len(nraw) > 1 and nraw[0] == 0) or (len(eraw) > 1 and eraw[0] == 0):
            return None
        n, e = int.from_bytes(nraw, "big"), int.from_bytes(eraw, "big")
        if n < 3 or not n & 1 or e < 3 or not e & 1:
            return None
        bits = n.bit_length()
        canonical = {"e": document["e"], "kty": "RSA", "n": document["n"]}
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            rsa.RSAPublicNumbers(e, n).public_key()
        except Exception:
            return None
    elif kty == "EC" and curve and type(document.get("x")) is str and type(document.get("y")) is str:
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            curve_info = {"P-256": (ec.SECP256R1, 32), "P-384": (ec.SECP384R1, 48),
                          "P-521": (ec.SECP521R1, 66)}[curve]
        except (ImportError, KeyError):
            return None
        xraw, yraw = _b64u_decode(document["x"], MAX_KEY_BYTES), _b64u_decode(document["y"], MAX_KEY_BYTES)
        if not xraw or not yraw or len(xraw) != curve_info[1] or len(yraw) != curve_info[1]:
            return None
        try:
            ec.EllipticCurvePublicNumbers(int.from_bytes(xraw, "big"), int.from_bytes(yraw, "big"),
                                          curve_info[0]()).public_key()
        except Exception:
            return None
        bits = curve_info[0]().key_size
        canonical = {"crv": curve, "kty": "EC", "x": document["x"], "y": document["y"]}
    elif kty == "OKP" and curve and type(document.get("x")) is str:
        xraw = _b64u_decode(document["x"], MAX_KEY_BYTES)
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, x25519, x448
            loaders = {"Ed25519": (ed25519.Ed25519PublicKey, 32), "Ed448": (ed448.Ed448PublicKey, 57),
                       "X25519": (x25519.X25519PublicKey, 32), "X448": (x448.X448PublicKey, 56)}
            loader, expected = loaders[curve]
        except (ImportError, KeyError):
            return None
        if not xraw or len(xraw) != expected:
            return None
        try:
            loader.from_public_bytes(xraw)
        except Exception:
            return None
        bits = len(xraw) * 8
        canonical = {"crv": curve, "kty": "OKP", "x": document["x"]}
    elif kty == "oct" and type(document.get("k")) is str:
        key = _b64u_decode(document["k"], MAX_KEY_BYTES)
        if not key:
            return None
        bits = len(key) * 8
        warnings.append("symmetric_key_material_present")
        canonical = {"k": document["k"], "kty": "oct"}
    elif kty in {"RSA", "EC", "OKP", "oct"}:
        return None
    else:
        warnings.append("unsupported_or_incomplete_key_type")
    if canonical is not None:
        try:
            encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        except (TypeError, ValueError, RecursionError):
            return None
        thumbprint = base64.urlsafe_b64encode(hashlib.sha256(encoded).digest()).decode().rstrip("=")
    return JWKReport(kty, document.get("kid") if type(document.get("kid")) is str else None,
                     document.get("alg") if type(document.get("alg")) is str else None,
                     document.get("use") if type(document.get("use")) is str else None,
                     bits, curve, has_private, thumbprint, tuple(warnings))
