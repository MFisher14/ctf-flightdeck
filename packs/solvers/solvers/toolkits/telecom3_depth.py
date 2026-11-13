#!/usr/bin/env python3
"""Bounded offline depth analysis for SRTP/SRTCP, SIP, GTPv2-C, and PFCP.

This module only decodes supplied artifacts.  It never opens a socket, derives a
password, or mutates a carrier/VoIP endpoint.  Existing ``net_voip`` and
``telecom`` readers remain the broad packet decoders; this module adds the
cryptographic verification and multi-message state that they intentionally lack.

CLI examples::

  telecom3_depth.py srtp packet.bin --master-key HEX --master-salt HEX
  telecom3_depth.py sip message.sip
  telecom3_depth.py gtpc pdu1.bin pdu2.bin
  telecom3_depth.py pfcp pdu1.bin pdu2.bin
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import sys
from collections import OrderedDict
from functools import wraps
from pathlib import Path


MAX_PACKET = 1024 * 1024
MAX_SIP = 4 * 1024 * 1024
MAX_TRACE_MESSAGES = 4096
MAX_TRACE_BYTES = 32 * 1024 * 1024
MAX_IES = 4096
MAX_IE_DEPTH = 8


class Telecom3Error(ValueError):
    """Malformed, unsupported, unauthenticated, or oversized telecom input."""


def _closed(function):
    """Make every public parser expose one exception type and no library leaks."""

    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Telecom3Error:
            raise
        except Exception as exc:  # parser boundary: never leak stdlib/backend errors
            raise Telecom3Error(
                f"{function.__name__} failed: {type(exc).__name__}"
            ) from exc

    return wrapped


def _bytes(value, name, maximum=MAX_PACKET, allow_empty=False):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise Telecom3Error(f"{name} must be bytes")
    data = bytes(value)
    if (not allow_empty and not data) or len(data) > maximum:
        qualifier = "0.." if allow_empty else "1.."
        raise Telecom3Error(f"{name} size must be {qualifier}{maximum} bytes")
    return data


def _key_bytes(value, name, length):
    if isinstance(value, str):
        if len(value) != length * 2 or not re.fullmatch(r"[0-9A-Fa-f]+", value):
            raise Telecom3Error(f"{name} must be {length} bytes or {length * 2} hex digits")
        value = bytes.fromhex(value)
    data = _bytes(value, name, maximum=length)
    if len(data) != length:
        raise Telecom3Error(f"{name} must be exactly {length} bytes")
    return data


def _text_or_none(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _u24(data):
    if len(data) != 3:
        raise Telecom3Error("invalid 24-bit integer")
    return int.from_bytes(data, "big")


# ---------------------------------------------------------------------------
# SRTP / SRTCP (RFC 3711, AES-CM with HMAC-SHA1 profiles)


_SRTP_PROFILES = {
    "AES_CM_128_HMAC_SHA1_80": {"srtp_tag": 10, "srtcp_tag": 10},
    "AES_CM_128_HMAC_SHA1_32": {"srtp_tag": 4, "srtcp_tag": 10},
}


def _profile(name):
    if not isinstance(name, str) or name not in _SRTP_PROFILES:
        raise Telecom3Error("unsupported SRTP protection profile")
    return _SRTP_PROFILES[name]


@_closed
def parse_srtp_context(value, profile=None):
    """Parse one RFC 4568 SDES ``inline:`` key context.

    The returned key material is intended for explicit, supplied-key offline
    decryption.  Only the two mandatory AES-CM/HMAC-SHA1 profiles are accepted.
    """

    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise Telecom3Error("SRTP context must be ASCII") from exc
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise Telecom3Error("SRTP context must be a bounded string")
    text = value.strip()
    if text.lower().startswith("a=crypto:"):
        if text.count("inline:") != 1:
            raise Telecom3Error("exactly one inline key context is required")
        parts = text.split()
        if len(parts) < 3:
            raise Telecom3Error("incomplete SDES crypto attribute")
        attr_profile = parts[1]
        if profile is not None and profile != attr_profile:
            raise Telecom3Error("profile conflicts with SDES attribute")
        profile = attr_profile
        contexts = [part for part in parts[2:] if "inline:" in part]
        if len(contexts) != 1:
            raise Telecom3Error("exactly one inline key context is required")
        text = contexts[0].split(";", 1)[0]
    if profile is None:
        profile = "AES_CM_128_HMAC_SHA1_80"
    _profile(profile)
    if not text.startswith("inline:"):
        raise Telecom3Error("expected an inline SRTP key context")
    fields = text[7:].split("|")
    if not 1 <= len(fields) <= 3 or not fields[0]:
        raise Telecom3Error("malformed inline SRTP key context")
    encoded = fields[0]
    if len(encoded) > 256 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", encoded):
        raise Telecom3Error("invalid base64 key material")
    try:
        padded = encoded + "=" * ((-len(encoded)) % 4)
        material = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Telecom3Error("invalid base64 key material") from exc
    if len(material) != 30:
        raise Telecom3Error("AES-CM inline material must be 16-byte key plus 14-byte salt")
    lifetime = None
    if len(fields) >= 2 and fields[1]:
        life = fields[1]
        if re.fullmatch(r"2\^[0-9]{1,2}", life):
            power = int(life[2:])
            if power > 48:
                raise Telecom3Error("SRTP lifetime exceeds the supported bound")
            lifetime = 1 << power
        elif life.isdigit() and len(life) <= 15 and int(life) <= (1 << 48):
            lifetime = int(life)
        else:
            raise Telecom3Error("invalid SRTP lifetime")
    mki = b""
    if len(fields) == 3 and fields[2]:
        m = re.fullmatch(r"(0[xX][0-9A-Fa-f]+|[0-9]+):([0-9]+)", fields[2])
        if not m:
            raise Telecom3Error("invalid MKI value:length")
        mki_len = int(m.group(2))
        if not 1 <= mki_len <= 128:
            raise Telecom3Error("MKI length must be 1..128 octets")
        mki_value = int(m.group(1), 0)
        if mki_value >= 1 << (8 * mki_len):
            raise Telecom3Error("MKI value does not fit its declared length")
        mki = mki_value.to_bytes(mki_len, "big")
    return {
        "profile": profile,
        "master_key_hex": material[:16].hex(),
        "master_salt_hex": material[16:].hex(),
        "lifetime_packets": lifetime,
        "mki_hex": mki.hex(),
        "mki_length": len(mki),
    }


def _aes_ecb_block(key, block):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise Telecom3Error("SRTP requires the installed cryptography package") from exc
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _aes_ctr(key, iv, data):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise Telecom3Error("SRTP requires the installed cryptography package") from exc
    cryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return cryptor.update(data) + cryptor.finalize()


def _kdf(master_key, master_salt, label, size):
    # RFC 3711 section 4.3.3, kdr=0: x=(master_salt XOR (label<<48))<<16.
    key_id = bytearray(14)
    key_id[7] = label
    mixed = bytes(a ^ b for a, b in zip(master_salt, key_id)) + b"\x00\x00"
    base = int.from_bytes(mixed, "big")
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(_aes_ecb_block(master_key, ((base + counter) & ((1 << 128) - 1)).to_bytes(16, "big")))
        counter += 1
    return bytes(output[:size])


def _session_keys(master_key, master_salt, rtcp):
    offset = 3 if rtcp else 0
    return (
        _kdf(master_key, master_salt, offset, 16),
        _kdf(master_key, master_salt, offset + 1, 20),
        _kdf(master_key, master_salt, offset + 2, 14),
    )


@_closed
def derive_srtp_keys(master_key, master_salt, rtcp=False):
    """Derive RFC 3711 AES-CM encryption/authentication/salting keys (kdr=0)."""

    key = _key_bytes(master_key, "master key", 16)
    salt = _key_bytes(master_salt, "master salt", 14)
    if not isinstance(rtcp, bool):
        raise Telecom3Error("rtcp must be boolean")
    enc, auth, session_salt = _session_keys(key, salt, rtcp)
    return {
        "kind": "SRTCP" if rtcp else "SRTP",
        "encryption_key_hex": enc.hex(),
        "authentication_key_hex": auth.hex(),
        "salting_key_hex": session_salt.hex(),
    }


def _rtp_header_length(packet):
    if len(packet) < 12 or packet[0] >> 6 != 2:
        raise Telecom3Error("invalid RTP version or truncated header")
    offset = 12 + 4 * (packet[0] & 0x0F)
    if offset > len(packet):
        raise Telecom3Error("truncated RTP CSRC list")
    if packet[0] & 0x10:
        if offset + 4 > len(packet):
            raise Telecom3Error("truncated RTP extension header")
        words = int.from_bytes(packet[offset + 2 : offset + 4], "big")
        offset += 4 + words * 4
        if offset > len(packet):
            raise Telecom3Error("truncated RTP extension value")
    return offset


def _expected_mki(value, length):
    if not isinstance(length, int) or isinstance(length, bool) or not 0 <= length <= 128:
        raise Telecom3Error("MKI length must be 0..128")
    if value is None:
        return None, length
    if isinstance(value, str):
        if len(value) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", value):
            raise Telecom3Error("expected MKI must be bytes or hexadecimal")
        value = bytes.fromhex(value)
    value = _bytes(value, "expected MKI", maximum=128, allow_empty=True)
    if length == 0:
        length = len(value)
    if len(value) != length:
        raise Telecom3Error("expected MKI length mismatch")
    return value, length


def _srtp_iv(session_salt, ssrc, packet_index):
    value = (int.from_bytes(session_salt, "big") << 16) ^ (ssrc << 64) ^ (packet_index << 16)
    return value.to_bytes(16, "big")


@_closed
def decrypt_srtp(
    packet,
    *,
    master_key,
    master_salt,
    roc=0,
    profile="AES_CM_128_HMAC_SHA1_80",
    mki_length=0,
    expected_mki=None,
):
    """Authenticate and decrypt one RFC 3711 SRTP packet with supplied keys."""

    data = _bytes(packet, "SRTP packet")
    key = _key_bytes(master_key, "master key", 16)
    salt = _key_bytes(master_salt, "master salt", 14)
    cfg = _profile(profile)
    if not isinstance(roc, int) or isinstance(roc, bool) or not 0 <= roc <= 0xFFFFFFFF:
        raise Telecom3Error("ROC must be a 32-bit unsigned integer")
    expected, mki_length = _expected_mki(expected_mki, mki_length)
    tag_length = cfg["srtp_tag"]
    header_length = _rtp_header_length(data)
    if len(data) < header_length + mki_length + tag_length:
        raise Telecom3Error("truncated SRTP ciphertext/MKI/tag")
    protected_end = len(data) - mki_length - tag_length
    mki = data[protected_end : protected_end + mki_length]
    tag = data[-tag_length:]
    if expected is not None and not hmac.compare_digest(mki, expected):
        raise Telecom3Error("SRTP MKI does not match the selected key context")
    enc, auth, session_salt = _session_keys(key, salt, False)
    authenticated = data[:protected_end] + roc.to_bytes(4, "big")
    calculated = hmac.new(auth, authenticated, hashlib.sha1).digest()[:tag_length]
    if not hmac.compare_digest(tag, calculated):
        raise Telecom3Error("SRTP authentication failed")
    seq = int.from_bytes(data[2:4], "big")
    timestamp = int.from_bytes(data[4:8], "big")
    ssrc = int.from_bytes(data[8:12], "big")
    index = (roc << 16) | seq
    plaintext = _aes_ctr(enc, _srtp_iv(session_salt, ssrc, index), data[header_length:protected_end])
    media = plaintext
    padding = 0
    if data[0] & 0x20:
        if not plaintext or plaintext[-1] == 0 or plaintext[-1] > len(plaintext):
            raise Telecom3Error("invalid decrypted RTP padding")
        padding = plaintext[-1]
        media = plaintext[:-padding]
    plain_packet = data[:header_length] + plaintext
    return {
        "protocol": "SRTP",
        "profile": profile,
        "sequence": seq,
        "roc": roc,
        "packet_index": index,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "payload_type": data[1] & 0x7F,
        "marker": bool(data[1] & 0x80),
        "header_length": header_length,
        "mki_hex": mki.hex(),
        "auth_tag_hex": tag.hex(),
        "authentication_verified": True,
        "padding_octets": padding,
        "payload_hex": media.hex(),
        "payload_text": _text_or_none(media),
        "plaintext_packet_hex": plain_packet.hex(),
    }


@_closed
def decrypt_srtcp(
    packet,
    *,
    master_key,
    master_salt,
    profile="AES_CM_128_HMAC_SHA1_80",
    mki_length=0,
    expected_mki=None,
):
    """Authenticate and decrypt one RFC 3711 SRTCP packet with supplied keys."""

    data = _bytes(packet, "SRTCP packet")
    key = _key_bytes(master_key, "master key", 16)
    salt = _key_bytes(master_salt, "master salt", 14)
    cfg = _profile(profile)
    expected, mki_length = _expected_mki(expected_mki, mki_length)
    tag_length = cfg["srtcp_tag"]
    if len(data) < 8 + 4 + mki_length + tag_length or data[0] >> 6 != 2:
        raise Telecom3Error("truncated or invalid SRTCP packet")
    index_offset = len(data) - tag_length - mki_length - 4
    index_word = int.from_bytes(data[index_offset : index_offset + 4], "big")
    protected = data[: index_offset + 4]
    mki = data[index_offset + 4 : index_offset + 4 + mki_length]
    tag = data[-tag_length:]
    if expected is not None and not hmac.compare_digest(mki, expected):
        raise Telecom3Error("SRTCP MKI does not match the selected key context")
    enc, auth, session_salt = _session_keys(key, salt, True)
    calculated = hmac.new(auth, protected, hashlib.sha1).digest()[:tag_length]
    if not hmac.compare_digest(tag, calculated):
        raise Telecom3Error("SRTCP authentication failed")
    encrypted = bool(index_word & 0x80000000)
    index = index_word & 0x7FFFFFFF
    ssrc = int.from_bytes(data[4:8], "big")
    body = data[8:index_offset]
    if encrypted:
        body = _aes_ctr(enc, _srtp_iv(session_salt, ssrc, index), body)
    plain = data[:8] + body
    return {
        "protocol": "SRTCP",
        "profile": profile,
        "packet_type": data[1],
        "ssrc": ssrc,
        "index": index,
        "encrypted": encrypted,
        "mki_hex": mki.hex(),
        "auth_tag_hex": tag.hex(),
        "authentication_verified": True,
        "payload_hex": body.hex(),
        "plaintext_packet_hex": plain.hex(),
    }


# ---------------------------------------------------------------------------
# SIP Digest and REGISTER / MESSAGE flow analysis


def _sip_header_block(data):
    marker = data.find(b"\r\n\r\n")
    separator = 4
    if marker < 0:
        marker = data.find(b"\n\n")
        separator = 2
    if marker < 0:
        raise Telecom3Error("SIP header terminator is missing")
    return data[:marker], data[marker + separator :]


def _sip_headers(header):
    try:
        text = header.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Telecom3Error("SIP headers must be UTF-8/ASCII") from exc
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or len(lines[0]) > 8192:
        raise Telecom3Error("invalid SIP start line")
    unfolded = []
    for line in lines[1:]:
        if len(line) > 8192:
            raise Telecom3Error("SIP header line exceeds limit")
        if line[:1] in (" ", "\t"):
            if not unfolded:
                raise Telecom3Error("orphan SIP header continuation")
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)
    compact = {"f": "from", "t": "to", "m": "contact", "i": "call-id", "v": "via", "c": "content-type", "l": "content-length"}
    headers = OrderedDict()
    for line in unfolded:
        if not line:
            continue
        if ":" not in line:
            raise Telecom3Error("malformed SIP header line")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            raise Telecom3Error("invalid SIP header name")
        name = compact.get(name, name)
        headers.setdefault(name, []).append(value.strip())
    return lines[0], headers


@_closed
def parse_sip_message(data):
    """Strictly frame one SIP message and extend ``net_voip.parse_sip`` with its body."""

    raw = _bytes(data, "SIP message", maximum=MAX_SIP)
    header, body = _sip_header_block(raw)
    start_line, headers = _sip_headers(header)
    try:
        from net_voip import parse_digest, parse_sip
    except ImportError as exc:
        raise Telecom3Error("existing net_voip parser is unavailable") from exc
    base = parse_sip(header + b"\r\n\r\n")
    if base is None:
        raise Telecom3Error("invalid SIP request/status line")
    lengths = headers.get("content-length", [])
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]) or len(lengths[0]) > 10:
            raise Telecom3Error("invalid or duplicate SIP Content-Length")
        expected = int(lengths[0])
        if expected != len(body):
            raise Telecom3Error("SIP Content-Length does not match the framed body")
    elif body:
        raise Telecom3Error("SIP body requires an explicit Content-Length")
    first = start_line.split(" ")
    record = dict(base)
    record["start_line"] = start_line
    record["request_uri"] = first[1] if base["kind"] == "request" else None
    record["reason"] = " ".join(first[2:]) if base["kind"] == "response" and len(first) > 2 else None
    record["headers"] = dict(headers)
    record["content_type"] = headers.get("content-type", [None])[0]
    record["authorizations"] = [
        parsed
        for name in ("authorization", "proxy-authorization")
        for value in headers.get(name, [])
        if (parsed := parse_digest(value)) is not None
    ]
    record["challenges"] = [
        parsed
        for name in ("www-authenticate", "proxy-authenticate")
        for value in headers.get(name, [])
        if (parsed := parse_digest(value)) is not None
    ]
    record["body_length"] = len(body)
    record["body_hex"] = body.hex()
    record["body_text"] = _text_or_none(body)
    return record


def _digest_hash(name):
    normalized = name.upper()
    if normalized == "MD5":
        return lambda data: hashlib.md5(data).hexdigest()  # noqa: S324 - protocol-mandated
    if normalized == "SHA-256":
        return lambda data: hashlib.sha256(data).hexdigest()
    if normalized == "SHA-512-256":
        return lambda data: hashlib.new("sha512_256", data).hexdigest()
    raise Telecom3Error("unsupported SIP Digest algorithm")


@_closed
def compute_sip_digest(
    *,
    method,
    uri,
    username,
    realm,
    password,
    nonce,
    algorithm="MD5",
    qop=None,
    nc=None,
    cnonce=None,
    entity_body=b"",
):
    """Compute the RFC 7616 Digest ``response`` value (including ``-sess``)."""

    values = {"method": method, "uri": uri, "username": username, "realm": realm, "password": password, "nonce": nonce}
    for name, value in values.items():
        if not isinstance(value, str) or not value or len(value) > 8192:
            raise Telecom3Error(f"{name} must be a bounded non-empty string")
    if not isinstance(algorithm, str):
        raise Telecom3Error("algorithm must be a string")
    session = algorithm.lower().endswith("-sess")
    base_algorithm = algorithm[:-5] if session else algorithm
    digest = _digest_hash(base_algorithm)
    if isinstance(entity_body, str):
        entity_body = entity_body.encode("utf-8")
    entity_body = _bytes(entity_body, "Digest entity body", maximum=MAX_SIP, allow_empty=True)
    ha1 = digest(f"{username}:{realm}:{password}".encode("utf-8"))
    if session:
        if not isinstance(cnonce, str) or not cnonce:
            raise Telecom3Error("-sess Digest requires cnonce")
        ha1 = digest(f"{ha1}:{nonce}:{cnonce}".encode("utf-8"))
    qop_norm = qop.lower() if isinstance(qop, str) else None
    if qop_norm not in (None, "auth", "auth-int"):
        raise Telecom3Error("Digest qop must be auth or auth-int")
    if qop_norm == "auth-int":
        ha2 = digest(f"{method}:{uri}:{digest(entity_body)}".encode("utf-8"))
    else:
        ha2 = digest(f"{method}:{uri}".encode("utf-8"))
    if qop_norm is None:
        response = digest(f"{ha1}:{nonce}:{ha2}".encode("ascii"))
    else:
        if not isinstance(nc, str) or not re.fullmatch(r"[0-9A-Fa-f]{8}", nc):
            raise Telecom3Error("Digest nc must be exactly eight hexadecimal digits")
        if not isinstance(cnonce, str) or not cnonce:
            raise Telecom3Error("Digest qop requires cnonce")
        response = digest(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop_norm}:{ha2}".encode("utf-8"))
    return response


@_closed
def verify_sip_digest(message, password):
    """Verify a request's Authorization response with an explicitly supplied password."""

    record = parse_sip_message(message) if isinstance(message, (bytes, bytearray, memoryview)) else message
    if not isinstance(record, dict) or record.get("kind") != "request":
        raise Telecom3Error("Digest verification requires a parsed SIP request")
    if not isinstance(password, str) or not password:
        raise Telecom3Error("password must be a non-empty string")
    auth = record.get("authorization")
    if not isinstance(auth, dict):
        raise Telecom3Error("SIP request has no Digest Authorization")
    required = ("username", "realm", "nonce", "uri", "response")
    if any(not isinstance(auth.get(name), str) or not auth[name] for name in required):
        raise Telecom3Error("Digest Authorization is missing required parameters")
    body = bytes.fromhex(record.get("body_hex", ""))
    expected = compute_sip_digest(
        method=record.get("method"),
        uri=auth["uri"],
        username=auth["username"],
        realm=auth["realm"],
        password=password,
        nonce=auth["nonce"],
        algorithm=auth.get("algorithm", "MD5"),
        qop=auth.get("qop"),
        nc=auth.get("nc"),
        cnonce=auth.get("cnonce"),
        entity_body=body,
    )
    actual = auth["response"].lower()
    return {
        "verified": hmac.compare_digest(expected, actual),
        "expected": expected,
        "actual": actual,
        "username": auth["username"],
        "algorithm": auth.get("algorithm", "MD5"),
        "qop": auth.get("qop"),
        # RFC 3261 permits a proxy to rewrite Request-URI: flag, do not reject.
        "authorization_uri": auth["uri"],
        "request_uri": record.get("request_uri"),
        "uri_matches_request": auth["uri"] == record.get("request_uri"),
    }


def _cseq(record):
    value = record.get("cseq")
    if not isinstance(value, str):
        return None, None
    match = re.fullmatch(r"\s*([0-9]{1,10})\s+([A-Za-z]+)\s*", value)
    if not match:
        return None, None
    return int(match.group(1)), match.group(2).upper()


def _sip_transaction_key(record):
    number, method = _cseq(record)
    via = (record.get("headers") or {}).get("via", [None])[0]
    branch = None
    if isinstance(via, str):
        match = re.search(r"(?:^|;)\s*branch\s*=\s*([^;\s]+)", via, re.IGNORECASE)
        branch = match.group(1) if match else None
    return record.get("call_id"), number, method, branch


@_closed
def analyze_sip_trace(messages, credentials=None):
    """Correlate bounded SIP REGISTER and MESSAGE transactions by Call-ID/CSeq."""

    if not isinstance(messages, (list, tuple)) or not 1 <= len(messages) <= MAX_TRACE_MESSAGES:
        raise Telecom3Error("SIP trace must contain 1..4096 messages")
    if credentials is None:
        credentials = {}
    if not isinstance(credentials, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in credentials.items()):
        raise Telecom3Error("credentials must map usernames to supplied passwords")
    records = []
    total = 0
    for raw in messages:
        raw = _bytes(raw, "SIP trace message", maximum=MAX_SIP)
        total += len(raw)
        if total > MAX_TRACE_BYTES:
            raise Telecom3Error("SIP trace exceeds aggregate byte limit")
        record = parse_sip_message(raw)
        auth = record.get("authorization") or {}
        username = auth.get("username")
        if username in credentials:
            record["digest_verification"] = verify_sip_digest(raw, credentials[username])
        records.append(record)
    responses = {}
    challenges = set()
    for index, record in enumerate(records):
        _, number, method, _ = _sip_transaction_key(record)
        key = _sip_transaction_key(record)
        if record.get("kind") == "response":
            responses.setdefault(key, []).append((index, record.get("status")))
            if record.get("status") in (401, 407):
                challenges.add((record.get("call_id"), method))
    registrations = []
    instant_messages = []
    nonce_counters = {}
    replay_warnings = []
    for index, record in enumerate(records):
        if record.get("kind") != "request":
            continue
        _, number, method, _ = _sip_transaction_key(record)
        key = _sip_transaction_key(record)
        later = [status for response_index, status in responses.get(key, []) if response_index > index]
        final_status = later[-1] if later else None
        auth = record.get("authorization") or {}
        if auth.get("qop") and auth.get("nc") and auth.get("nonce") and auth.get("username"):
            counter_key = (auth.get("username"), auth.get("nonce"), auth.get("cnonce"))
            counter = int(auth["nc"], 16) if re.fullmatch(r"[0-9A-Fa-f]{8}", auth["nc"]) else None
            previous = nonce_counters.get(counter_key)
            if counter is not None and previous is not None and counter <= previous:
                replay_warnings.append({"message_index": index, "username": auth["username"], "nc": auth["nc"]})
            if counter is not None:
                nonce_counters[counter_key] = counter
        if method == "REGISTER":
            registrations.append({
                "message_index": index,
                "call_id": record.get("call_id"),
                "cseq": number,
                "registrar_uri": record.get("request_uri"),
                "address_of_record": record.get("to"),
                "contact": record.get("contact"),
                "challenged": (record.get("call_id"), "REGISTER") in challenges,
                "authenticated": bool(auth),
                "digest_verified": (record.get("digest_verification") or {}).get("verified"),
                "final_status": final_status,
                "accepted": final_status is not None and 200 <= final_status < 300,
            })
        elif method == "MESSAGE":
            instant_messages.append({
                "message_index": index,
                "call_id": record.get("call_id"),
                "cseq": number,
                "from": record.get("from"),
                "to": record.get("to"),
                "request_uri": record.get("request_uri"),
                "content_type": record.get("content_type"),
                "body_hex": record.get("body_hex"),
                "body_text": record.get("body_text"),
                "final_status": final_status,
                "accepted": final_status in (200, 202),
                "delivery_confirmed": final_status == 200,
            })
    return {
        "protocol": "SIP",
        "message_count": len(records),
        "registrations": registrations,
        "instant_messages": instant_messages,
        "digest_replay_warnings": replay_warnings,
    }


# ---------------------------------------------------------------------------
# GTPv2-C transaction / bearer correlation (broad fields reuse telecom.py)


_GTPC_MESSAGES = {
    32: ("create_session", "request"), 33: ("create_session", "response"),
    34: ("modify_bearer", "request"), 35: ("modify_bearer", "response"),
    36: ("delete_session", "request"), 37: ("delete_session", "response"),
    95: ("create_bearer", "request"), 96: ("create_bearer", "response"),
    97: ("update_bearer", "request"), 98: ("update_bearer", "response"),
    99: ("delete_bearer", "request"), 100: ("delete_bearer", "response"),
}

_GTPC_IE_NAMES = {1: "IMSI", 2: "Cause", 71: "APN", 73: "EBI", 76: "MSISDN", 87: "F-TEID", 93: "Bearer Context"}


def _tbcd(value):
    digits = []
    for byte in value:
        for nibble in (byte & 15, byte >> 4):
            if nibble == 15:
                return "".join(digits)
            if nibble > 9:
                raise Telecom3Error("invalid TBCD digit")
            digits.append(str(nibble))
    return "".join(digits)


def _apn(value):
    labels = []
    offset = 0
    while offset < len(value):
        size = value[offset]
        offset += 1
        if size == 0 or size > 63 or offset + size > len(value):
            raise Telecom3Error("invalid APN/DNN labels")
        try:
            labels.append(value[offset : offset + size].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise Telecom3Error("non-ASCII APN/DNN") from exc
        offset += size
    return ".".join(labels)


def _gtpc_ie_value(kind, value):
    if kind == 1:
        return {"imsi": _tbcd(value)}
    if kind == 2:
        if not value:
            raise Telecom3Error("empty GTP Cause IE")
        return {"cause": value[0]}
    if kind == 71:
        return {"apn": _apn(value)}
    if kind == 73:
        if len(value) != 1:
            raise Telecom3Error("GTP EBI IE must contain one octet")
        return {"ebi": value[0] & 0x0F}
    if kind == 76:
        if len(value) < 2:
            raise Telecom3Error("truncated GTP MSISDN IE")
        return {"digits": _tbcd(value[1:])}
    if kind == 87:
        if len(value) < 5:
            raise Telecom3Error("truncated GTP F-TEID IE")
        flags = value[0]
        offset = 5
        decoded = {"interface_type": flags & 0x3F, "teid": int.from_bytes(value[1:5], "big")}
        if flags & 0x80:
            if offset + 4 > len(value):
                raise Telecom3Error("truncated GTP F-TEID IPv4 address")
            decoded["ipv4"] = str(ipaddress.IPv4Address(value[offset : offset + 4]))
            offset += 4
        if flags & 0x40:
            if offset + 16 > len(value):
                raise Telecom3Error("truncated GTP F-TEID IPv6 address")
            decoded["ipv6"] = str(ipaddress.IPv6Address(value[offset : offset + 16]))
            offset += 16
        if offset != len(value):
            raise Telecom3Error("unexpected bytes in GTP F-TEID IE")
        return decoded
    return {"value_hex": value.hex()}


def _gtpc_ies(data, depth, budget):
    if depth > MAX_IE_DEPTH:
        raise Telecom3Error("GTP grouped IE nesting limit exceeded")
    ies = []
    offset = 0
    while offset < len(data):
        budget[0] -= 1
        if budget[0] < 0:
            raise Telecom3Error("GTP IE count limit exceeded")
        if offset + 4 > len(data):
            raise Telecom3Error("truncated GTP IE header")
        kind = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 3], "big")
        instance = data[offset + 3] & 0x0F
        offset += 4
        if offset + length > len(data):
            raise Telecom3Error("truncated GTP IE value")
        value = data[offset : offset + length]
        offset += length
        item = {"type": kind, "name": _GTPC_IE_NAMES.get(kind, f"IE-{kind}"), "instance": instance, "length": length}
        if kind == 93:
            item["children"] = _gtpc_ies(value, depth + 1, budget)
        else:
            item.update(_gtpc_ie_value(kind, value))
        ies.append(item)
    return ies


def _walk_ies(ies):
    for ie in ies:
        yield ie
        yield from _walk_ies(ie.get("children", []))


@_closed
def parse_gtpc_event(data):
    """Decode one exact GTPv2-C PDU and extract session-correlation fields."""

    raw = _bytes(data, "GTP-C PDU")
    if len(raw) < 8 or raw[0] >> 5 != 2:
        raise Telecom3Error("not a GTPv2-C PDU")
    if raw[0] & 0x10:
        raise Telecom3Error("piggybacked GTPv2 messages are not accepted as one PDU")
    total = 4 + int.from_bytes(raw[2:4], "big")
    if total != len(raw):
        raise Telecom3Error("GTP message length does not match input")
    has_teid = bool(raw[0] & 0x08)
    header_length = 12 if has_teid else 8
    if len(raw) < header_length:
        raise Telecom3Error("truncated GTPv2-C header")
    message_type = raw[1]
    if message_type not in _GTPC_MESSAGES:
        raise Telecom3Error("unsupported GTPv2-C session/bearer message")
    if not has_teid:
        raise Telecom3Error("GTPv2-C session/bearer message requires the T flag")
    teid = int.from_bytes(raw[4:8], "big") if has_teid else None
    seq_offset = 8 if has_teid else 4
    sequence = _u24(raw[seq_offset : seq_offset + 3])
    ies = _gtpc_ies(raw[header_length:], 0, [MAX_IES])
    flat = list(_walk_ies(ies))
    operation, direction = _GTPC_MESSAGES[message_type]
    record = {
        "protocol": "GTPv2-C", "message_type": message_type,
        "operation": operation, "direction": direction, "sequence": sequence,
        "teid_present": has_teid, "header_teid": teid, "ies": ies,
        "imsi": next((ie["imsi"] for ie in flat if "imsi" in ie), None),
        "apn": next((ie["apn"] for ie in flat if "apn" in ie), None),
        "cause": next((ie["cause"] for ie in flat if "cause" in ie), None),
        "bearer_ids": sorted({ie["ebi"] for ie in flat if "ebi" in ie}),
        "fteids": [{k: v for k, v in ie.items() if k in ("instance", "interface_type", "teid", "ipv4", "ipv6")} for ie in flat if "teid" in ie],
    }
    try:
        from telecom import parse_gtp
        record["base_decode"] = parse_gtp(raw)
    except ImportError:
        record["base_decode"] = None
    return record


def _trace_item(item, parser, name):
    src = dst = None
    if isinstance(item, dict):
        allowed = {"data", "src", "dst"}
        if set(item) - allowed or "data" not in item:
            raise Telecom3Error(f"{name} mapping accepts only data/src/dst")
        data, src, dst = item["data"], item.get("src"), item.get("dst")
        if src is not None and not isinstance(src, str) or dst is not None and not isinstance(dst, str):
            raise Telecom3Error(f"{name} endpoints must be strings")
    else:
        data = item
    return parser(data), src, dst, len(_bytes(data, name))


@_closed
def correlate_gtpc(pdus):
    """Correlate Create/Modify/Delete Session/Bearer GTPv2-C transactions."""

    if not isinstance(pdus, (list, tuple)) or not 1 <= len(pdus) <= MAX_TRACE_MESSAGES:
        raise Telecom3Error("GTP-C trace must contain 1..4096 PDUs")
    events = []
    total = 0
    for item in pdus:
        event, src, dst, size = _trace_item(item, parse_gtpc_event, "GTP-C PDU")
        total += size
        if total > MAX_TRACE_BYTES:
            raise Telecom3Error("GTP-C trace exceeds aggregate byte limit")
        event["src"], event["dst"] = src, dst
        events.append(event)
    sessions = []
    aliases = {}
    pending = {}
    transactions = []

    def alias_candidates(event):
        candidates = []
        if event["header_teid"] not in (None, 0):
            candidates.append((event.get("dst"), event["header_teid"]))
        candidates += [(event.get("src"), entry["teid"]) for entry in event["fteids"] if entry["teid"]]
        return candidates

    def session_for(event):
        candidates = alias_candidates(event)
        found = next((aliases[value] for value in candidates if value in aliases), None)
        if found is None:
            found = len(sessions)
            sessions.append({"session_id": f"gtp-{found + 1}", "state": "pending", "imsi": None, "apn": None, "teids": set(), "teid_aliases": set(), "bearers": set(), "timeline": []})
        for owner_and_value in candidates:
            aliases[owner_and_value] = found
            sessions[found]["teids"].add(owner_and_value[1])
            sessions[found]["teid_aliases"].add(owner_and_value)
        return found

    def alias_event(sid, event):
        for owner_and_value in alias_candidates(event):
            aliases[owner_and_value] = sid
            sessions[sid]["teids"].add(owner_and_value[1])
            sessions[sid]["teid_aliases"].add(owner_and_value)

    for index, event in enumerate(events):
        endpoint_key = (event.get("src"), event.get("dst")) if event.get("src") is not None else None
        key = (event["operation"], event["sequence"], endpoint_key)
        reverse_key = (event["operation"], event["sequence"], (event.get("dst"), event.get("src")) if endpoint_key else None)
        if event["direction"] == "request":
            sid = session_for(event)
            pending[key] = (sid, index, event)
        else:
            match = pending.pop(reverse_key, None) or pending.pop(key, None)
            sid = match[0] if match else session_for(event)
            alias_event(sid, event)
            transactions.append({"operation": event["operation"], "sequence": event["sequence"], "request_index": match[1] if match else None, "response_index": index, "cause": event["cause"], "matched": match is not None})
        session = sessions[sid]
        if event["imsi"]:
            session["imsi"] = event["imsi"]
        if event["apn"]:
            session["apn"] = event["apn"]
        accepted = event["direction"] == "response" and event["cause"] == 16
        partial = event["direction"] == "response" and event["cause"] == 17
        if accepted and event["operation"] in ("create_session", "modify_bearer", "create_bearer", "update_bearer"):
            session["state"] = "active"
            proposed = match[2]["bearer_ids"] if match else []
            committed = event["bearer_ids"] or proposed
            session["bearers"].update(value for value in committed if value)
        elif partial:
            session["state"] = "partial"
        elif accepted and event["operation"] == "delete_bearer":
            requested = match[2]["bearer_ids"] if match else event["bearer_ids"]
            session["bearers"].difference_update(requested)
        elif accepted and event["operation"] == "delete_session":
            session["state"] = "deleted"
            session["bearers"].clear()
        session["timeline"].append({"index": index, "operation": event["operation"], "direction": event["direction"], "sequence": event["sequence"], "cause": event["cause"], "bearer_ids": event["bearer_ids"]})
    rendered = []
    for session in sessions:
        rendered.append(dict(
            session,
            teids=sorted(session["teids"]),
            teid_aliases=[{"owner": owner, "teid": value} for owner, value in sorted(session["teid_aliases"], key=lambda pair: (str(pair[0]), pair[1]))],
            bearers=sorted(session["bearers"]),
        ))
    return {"protocol": "GTPv2-C", "event_count": len(events), "sessions": rendered, "transactions": transactions, "unanswered_requests": len(pending)}


# ---------------------------------------------------------------------------
# PFCP / N4 inventory and session correlation (3GPP TS 29.244)


_PFCP_MESSAGES = {
    1: ("heartbeat", "request"), 2: ("heartbeat", "response"),
    5: ("association_setup", "request"), 6: ("association_setup", "response"),
    7: ("association_update", "request"), 8: ("association_update", "response"),
    9: ("association_release", "request"), 10: ("association_release", "response"),
    12: ("node_report", "request"), 13: ("node_report", "response"),
    14: ("session_set_deletion", "request"), 15: ("session_set_deletion", "response"),
    50: ("session_establishment", "request"), 51: ("session_establishment", "response"),
    52: ("session_modification", "request"), 53: ("session_modification", "response"),
    54: ("session_deletion", "request"), 55: ("session_deletion", "response"),
    56: ("session_report", "request"), 57: ("session_report", "response"),
}

_PFCP_GROUPED = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 51, 54, 58, 59, 68, 77, 78, 79, 80, 83, 85, 86, 87, 99, 102, 105, 118, 127, 128, 129, 130}
_PFCP_IE_NAMES = {1: "Create PDR", 2: "PDI", 3: "Create FAR", 6: "Create URR", 7: "Create QER", 8: "Created PDR", 9: "Update PDR", 10: "Update FAR", 15: "Remove PDR", 16: "Remove FAR", 17: "Remove URR", 18: "Remove QER", 19: "Cause", 20: "Source Interface", 21: "F-TEID", 22: "Network Instance", 56: "PDR ID", 57: "F-SEID", 60: "Node ID", 81: "URR ID", 88: "BAR ID", 93: "UE IP Address", 96: "Recovery Time Stamp", 108: "FAR ID", 109: "QER ID", 124: "QFI", 159: "APN/DNN"}
_PFCP_RULE_GROUPS = {
    1: ("create", "pdr_ids", "pdr_id"), 3: ("create", "far_ids", "far_id"),
    6: ("create", "urr_ids", "urr_id"), 7: ("create", "qer_ids", "qer_id"),
    85: ("create", "bar_ids", "bar_id"),
    9: ("update", "pdr_ids", "pdr_id"), 10: ("update", "far_ids", "far_id"),
    13: ("update", "urr_ids", "urr_id"), 14: ("update", "qer_ids", "qer_id"),
    86: ("update", "bar_ids", "bar_id"),
    15: ("remove", "pdr_ids", "pdr_id"), 16: ("remove", "far_ids", "far_id"),
    17: ("remove", "urr_ids", "urr_id"), 18: ("remove", "qer_ids", "qer_id"),
    87: ("remove", "bar_ids", "bar_id"),
}


def _pfcp_ie_value(kind, value):
    if kind == 19:
        if len(value) != 1:
            raise Telecom3Error("PFCP Cause IE must contain one octet")
        return {"cause": value[0]}
    widths = {56: 2, 81: 4, 88: 1, 108: 4, 109: 4}
    keys = {56: "pdr_id", 81: "urr_id", 88: "bar_id", 108: "far_id", 109: "qer_id"}
    if kind in widths:
        if len(value) != widths[kind]:
            raise Telecom3Error(f"PFCP {_PFCP_IE_NAMES[kind]} has invalid length")
        return {keys[kind]: int.from_bytes(value, "big")}
    if kind == 57:
        if len(value) < 9:
            raise Telecom3Error("truncated PFCP F-SEID")
        flags = value[0]
        if flags & 0xFC:
            raise Telecom3Error("invalid PFCP F-SEID flags")
        expected = 9 + (4 if flags & 2 else 0) + (16 if flags & 1 else 0)
        if len(value) != expected:
            raise Telecom3Error("PFCP F-SEID length/flags mismatch")
        out = {"seid": int.from_bytes(value[1:9], "big")}
        offset = 9
        if flags & 2:
            out["ipv4"] = str(ipaddress.IPv4Address(value[offset : offset + 4])); offset += 4
        if flags & 1:
            out["ipv6"] = str(ipaddress.IPv6Address(value[offset : offset + 16]))
        return out
    if kind == 21:
        if not value:
            raise Telecom3Error("empty PFCP F-TEID")
        flags = value[0]
        choose = bool(flags & 4)
        offset = 1
        out = {"choose": choose, "choose_id_present": bool(flags & 8)}
        if not choose:
            if offset + 4 > len(value):
                raise Telecom3Error("truncated PFCP F-TEID TEID")
            out["teid"] = int.from_bytes(value[offset : offset + 4], "big"); offset += 4
            if flags & 1:
                if offset + 4 > len(value): raise Telecom3Error("truncated PFCP F-TEID IPv4")
                out["ipv4"] = str(ipaddress.IPv4Address(value[offset : offset + 4])); offset += 4
            if flags & 2:
                if offset + 16 > len(value): raise Telecom3Error("truncated PFCP F-TEID IPv6")
                out["ipv6"] = str(ipaddress.IPv6Address(value[offset : offset + 16])); offset += 16
        if flags & 8:
            if offset >= len(value): raise Telecom3Error("missing PFCP F-TEID choose-id")
            out["choose_id"] = value[offset]; offset += 1
        if offset != len(value): raise Telecom3Error("unexpected bytes in PFCP F-TEID")
        return out
    if kind == 60:
        if len(value) < 2:
            raise Telecom3Error("truncated PFCP Node ID")
        id_type = value[0] & 15
        if id_type == 0 and len(value) == 5:
            return {"node_id_type": "ipv4", "node_id": str(ipaddress.IPv4Address(value[1:]))}
        if id_type == 1 and len(value) == 17:
            return {"node_id_type": "ipv6", "node_id": str(ipaddress.IPv6Address(value[1:]))}
        if id_type == 2:
            return {"node_id_type": "fqdn", "node_id": _apn(value[1:])}
        raise Telecom3Error("invalid PFCP Node ID encoding")
    if kind in (22, 159):
        return {"network_instance" if kind == 22 else "apn_dnn": _apn(value)}
    if kind == 20:
        if len(value) != 1: raise Telecom3Error("PFCP Source Interface must contain one octet")
        return {"source_interface": value[0] & 15}
    if kind == 93:
        if not value: raise Telecom3Error("empty PFCP UE IP Address")
        flags, offset = value[0], 1
        out = {"source_or_destination": bool(flags & 4)}
        if flags & 2:
            if offset + 4 > len(value): raise Telecom3Error("truncated PFCP UE IPv4 address")
            out["ipv4"] = str(ipaddress.IPv4Address(value[offset : offset + 4])); offset += 4
        if flags & 1:
            if offset + 16 > len(value): raise Telecom3Error("truncated PFCP UE IPv6 address")
            out["ipv6"] = str(ipaddress.IPv6Address(value[offset : offset + 16])); offset += 16
        if offset != len(value): raise Telecom3Error("unexpected bytes in PFCP UE IP Address")
        return out
    if kind == 96:
        if len(value) != 4: raise Telecom3Error("PFCP Recovery Time Stamp must be four octets")
        return {"recovery_timestamp": int.from_bytes(value, "big")}
    if kind == 124:
        if len(value) != 1: raise Telecom3Error("PFCP QFI must contain one octet")
        return {"qfi": value[0] & 0x3F}
    if kind & 0x8000:
        if len(value) < 2: raise Telecom3Error("truncated enterprise-specific PFCP IE")
        return {"enterprise_id": int.from_bytes(value[:2], "big"), "value_hex": value[2:].hex()}
    return {"value_hex": value.hex()}


def _pfcp_ies(data, depth, budget):
    if depth > MAX_IE_DEPTH:
        raise Telecom3Error("PFCP grouped IE nesting limit exceeded")
    result = []
    offset = 0
    while offset < len(data):
        budget[0] -= 1
        if budget[0] < 0: raise Telecom3Error("PFCP IE count limit exceeded")
        if offset + 4 > len(data): raise Telecom3Error("truncated PFCP IE header")
        kind = int.from_bytes(data[offset : offset + 2], "big")
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
        if offset + length > len(data): raise Telecom3Error("truncated PFCP IE value")
        value = data[offset : offset + length]; offset += length
        item = {"type": kind, "name": _PFCP_IE_NAMES.get(kind, f"IE-{kind}"), "length": length}
        if kind in _PFCP_GROUPED:
            item["children"] = _pfcp_ies(value, depth + 1, budget)
        else:
            item.update(_pfcp_ie_value(kind, value))
        result.append(item)
    return result


def _pfcp_rule_changes(ies):
    names = ("pdr_ids", "far_ids", "qer_ids", "urr_ids", "bar_ids")
    changes = {action: {name: set() for name in names} for action in ("create", "update", "remove")}
    for grouped in ies:
        meaning = _PFCP_RULE_GROUPS.get(grouped["type"])
        if meaning is None:
            continue
        action, collection, field = meaning
        value = next((item[field] for item in _walk_ies(grouped.get("children", [])) if field in item), None)
        if value is not None:
            changes[action][collection].add(value)
    return {
        action: {name: sorted(values) for name, values in collections.items()}
        for action, collections in changes.items()
    }


@_closed
def parse_pfcp(data):
    """Decode one exact PFCP/N4 PDU, including bounded grouped IEs."""

    raw = _bytes(data, "PFCP PDU")
    if len(raw) < 8 or raw[0] >> 5 != 1:
        raise Telecom3Error("not a PFCP version-1 PDU")
    if raw[0] & 4:
        raise Telecom3Error("follow-on bundled PFCP PDUs require explicit splitting")
    if 4 + int.from_bytes(raw[2:4], "big") != len(raw):
        raise Telecom3Error("PFCP message length does not match input")
    message_type = raw[1]
    if message_type not in _PFCP_MESSAGES:
        raise Telecom3Error("unsupported PFCP message type")
    session = bool(raw[0] & 1)
    header_length = 16 if session else 8
    if len(raw) < header_length:
        raise Telecom3Error("truncated PFCP header")
    if message_type >= 50 and not session:
        raise Telecom3Error("PFCP session message requires S=1")
    seid = int.from_bytes(raw[4:12], "big") if session else None
    seq_offset = 12 if session else 4
    sequence = _u24(raw[seq_offset : seq_offset + 3])
    priority = raw[seq_offset + 3] >> 4 if raw[0] & 2 else None
    ies = _pfcp_ies(raw[header_length:], 0, [MAX_IES])
    flat = list(_walk_ies(ies))
    operation, direction = _PFCP_MESSAGES[message_type]
    ids = {"pdr_ids": sorted({ie["pdr_id"] for ie in flat if "pdr_id" in ie}), "far_ids": sorted({ie["far_id"] for ie in flat if "far_id" in ie}), "qer_ids": sorted({ie["qer_id"] for ie in flat if "qer_id" in ie}), "urr_ids": sorted({ie["urr_id"] for ie in flat if "urr_id" in ie}), "bar_ids": sorted({ie["bar_id"] for ie in flat if "bar_id" in ie})}
    return {
        "protocol": "PFCP", "message_type": message_type, "operation": operation,
        "direction": direction, "session_header": session, "seid": seid,
        "sequence": sequence, "priority": priority, "ies": ies,
        "cause": next((ie["cause"] for ie in flat if "cause" in ie), None),
        "fseids": [{k: v for k, v in ie.items() if k in ("seid", "ipv4", "ipv6")} for ie in flat if "seid" in ie],
        "node_ids": [ie["node_id"] for ie in flat if "node_id" in ie],
        "rule_ids": ids,
        "rule_changes": _pfcp_rule_changes(ies),
    }


@_closed
def correlate_pfcp(pdus):
    """Correlate PFCP request/response pairs and committed N4 session rule state."""

    if not isinstance(pdus, (list, tuple)) or not 1 <= len(pdus) <= MAX_TRACE_MESSAGES:
        raise Telecom3Error("PFCP trace must contain 1..4096 PDUs")
    events, total = [], 0
    for item in pdus:
        event, src, dst, size = _trace_item(item, parse_pfcp, "PFCP PDU")
        total += size
        if total > MAX_TRACE_BYTES: raise Telecom3Error("PFCP trace exceeds aggregate byte limit")
        event["src"], event["dst"] = src, dst
        events.append(event)
    sessions, aliases, pending, transactions = [], {}, {}, []

    def alias_candidates(event):
        values = []
        if event["seid"] not in (None, 0):
            values.append((event.get("dst"), event["seid"]))
        values += [(event.get("src"), item["seid"]) for item in event["fseids"] if item["seid"]]
        return values

    def find_session(event):
        values = alias_candidates(event)
        sid = next((aliases[value] for value in values if value in aliases), None)
        if sid is None:
            sid = len(sessions)
            sessions.append({"session_id": f"pfcp-{sid + 1}", "state": "pending", "seids": set(), "seid_aliases": set(), "pdr_ids": set(), "far_ids": set(), "qer_ids": set(), "urr_ids": set(), "bar_ids": set(), "timeline": []})
        for owner_and_value in values:
            aliases[owner_and_value] = sid
            sessions[sid]["seids"].add(owner_and_value[1])
            sessions[sid]["seid_aliases"].add(owner_and_value)
        return sid

    def alias_event(sid, event):
        for owner_and_value in alias_candidates(event):
            aliases[owner_and_value] = sid
            sessions[sid]["seids"].add(owner_and_value[1])
            sessions[sid]["seid_aliases"].add(owner_and_value)

    for index, event in enumerate(events):
        endpoint_key = (event.get("src"), event.get("dst")) if event.get("src") is not None else None
        key = (event["operation"], event["sequence"], endpoint_key)
        reverse = (event["operation"], event["sequence"], (event.get("dst"), event.get("src")) if endpoint_key else None)
        if event["direction"] == "request":
            sid = find_session(event); pending[key] = (sid, index, event)
        else:
            match = pending.pop(reverse, None) or pending.pop(key, None)
            sid = match[0] if match else find_session(event)
            alias_event(sid, event)
            transactions.append({"operation": event["operation"], "sequence": event["sequence"], "request_index": match[1] if match else None, "response_index": index, "cause": event["cause"], "matched": match is not None})
            if match and event["cause"] == 1:
                request = match[2]
                session = sessions[sid]
                if event["operation"] in ("session_establishment", "session_modification"):
                    session["state"] = "active"
                    for action in ("create", "update"):
                        for name, values in request["rule_changes"][action].items():
                            session[name].update(values)
                    for name, values in request["rule_changes"]["remove"].items():
                        session[name].difference_update(values)
                elif event["operation"] == "session_deletion":
                    session["state"] = "deleted"
                    for name in ("pdr_ids", "far_ids", "qer_ids", "urr_ids", "bar_ids"): session[name].clear()
            elif match and event["cause"] == 3:
                sessions[sid]["state"] = "partial"
        session = sessions[sid]
        session["timeline"].append({"index": index, "operation": event["operation"], "direction": event["direction"], "sequence": event["sequence"], "cause": event["cause"]})
    rendered = []
    for session in sessions:
        record = {key: sorted(value) if isinstance(value, set) else value for key, value in session.items() if key != "seid_aliases"}
        record["seid_aliases"] = [{"owner": owner, "seid": value} for owner, value in sorted(session["seid_aliases"], key=lambda pair: (str(pair[0]), pair[1]))]
        rendered.append(record)
    return {"protocol": "PFCP", "event_count": len(events), "sessions": rendered, "transactions": transactions, "unanswered_requests": len(pending)}


# ---------------------------------------------------------------------------
# Guarded offline CLI


def _read_file(path, maximum):
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(maximum + 1)
    except OSError as exc:
        raise Telecom3Error(f"cannot read {path}: {exc}") from exc
    if len(data) > maximum:
        raise Telecom3Error(f"{path} exceeds the {maximum}-byte input limit")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("srtp", "srtcp"):
        command = sub.add_parser(name, help=f"authenticate/decrypt one supplied-key {name.upper()} packet")
        command.add_argument("file")
        command.add_argument("--master-key", required=True, help="16-byte AES master key in hex")
        command.add_argument("--master-salt", required=True, help="14-byte master salt in hex")
        command.add_argument("--profile", choices=sorted(_SRTP_PROFILES), default="AES_CM_128_HMAC_SHA1_80")
        command.add_argument("--mki-length", type=int, default=0)
        command.add_argument("--expected-mki")
    sub.choices["srtp"].add_argument("--roc", type=int, default=0)
    sip = sub.add_parser("sip", help="decode one SIP message or correlate several")
    sip.add_argument("files", nargs="+")
    for name in ("gtpc", "pfcp"):
        command = sub.add_parser(name, help=f"decode/correlate offline {name.upper()} PDUs")
        command.add_argument("files", nargs="+")
    try:
        args = parser.parse_args(argv)
        if args.command == "srtp":
            result = decrypt_srtp(_read_file(args.file, MAX_PACKET), master_key=args.master_key, master_salt=args.master_salt, roc=args.roc, profile=args.profile, mki_length=args.mki_length, expected_mki=args.expected_mki)
        elif args.command == "srtcp":
            result = decrypt_srtcp(_read_file(args.file, MAX_PACKET), master_key=args.master_key, master_salt=args.master_salt, profile=args.profile, mki_length=args.mki_length, expected_mki=args.expected_mki)
        elif args.command == "sip":
            values = [_read_file(path, MAX_SIP) for path in args.files]
            result = parse_sip_message(values[0]) if len(values) == 1 else analyze_sip_trace(values)
        elif args.command == "gtpc":
            values = [_read_file(path, MAX_PACKET) for path in args.files]
            result = parse_gtpc_event(values[0]) if len(values) == 1 else correlate_gtpc(values)
        else:
            values = [_read_file(path, MAX_PACKET) for path in args.files]
            result = parse_pfcp(values[0]) if len(values) == 1 else correlate_pfcp(values)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Telecom3Error as exc:
        print(f"telecom3_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
