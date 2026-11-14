#!/usr/bin/env python3
"""Offline-only cookie, session-envelope, and CSRF reconnaissance.

This module consumes response bytes that another, scope-locked reader already fetched.  It
does not construct an HTTP client, resolve a host, send a request, forge or replay a cookie,
verify a signature, decrypt a value, execute JavaScript, or extract a proof.  Cookie and token
values never appear in its result: only bounded lengths, fingerprints, attribute facts, and
explicitly *unverified* structural metadata are returned.

Public API::

    analyze(header_pairs_or_response, body=None, source_url=None) -> dict
    analyze_response(response, source_url=None) -> dict

``header_pairs_or_response`` should normally contain WebClient's ordered
``response_header_pairs``.  A mapping of normalized headers is accepted as a degraded fallback,
but duplicate-cookie analysis is then necessarily incomplete.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import math
import re
import time
import urllib.parse
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from itertools import islice

import security_json as _security_json


MAX_HEADERS = 256
MAX_HEADER_NAME = 128
MAX_HEADER_VALUE = 16_384
MAX_COOKIES = 128
MAX_COOKIE_NAME = 256
MAX_COOKIE_VALUE = 8_192
MAX_ATTRIBUTES = 64
MAX_ATTRIBUTE_NAME = 128
MAX_BODY = 1_000_000
MAX_CSRF_TOKENS = 128
MAX_TOKEN = 4_096
MAX_DECODED = 16_384
MAX_JSON_KEYS = 96
MAX_FINDINGS = 256

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}\Z")
_B64STD = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_B64ANY = re.compile(r"[A-Za-z0-9_+/-]*={0,2}\Z")
_HEX = re.compile(r"[0-9A-Fa-f]+\Z")
_BASE62 = re.compile(r"[0-9A-Za-z]{1,16}\Z")
_CSRF_NAME = re.compile(r"(?i)(?:^|[_.-])(?:csrf|xsrf)(?:$|[_.-])|authenticity[_-]?token")
_SESSIONISH = re.compile(r"(?i)(?:session|sess|auth|identity|ticket|sid|jwt|token)")

_KNOWN_ATTRS = frozenset((
    "secure", "httponly", "partitioned", "samesite", "domain", "path",
    "max-age", "expires", "priority", "comment", "version",
))
_FLAG_ATTRS = frozenset(("secure", "httponly", "partitioned"))


def _halted(deadline=None, stop=None):
    try:
        if hasattr(stop, "is_set") and stop.is_set():
            return True
        return deadline is not None and time.time() >= float(deadline)
    except (TypeError, ValueError):
        return True


def _has_control(value):
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def _fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _safe_text(value, limit):
    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", "replace")
    if isinstance(value, bytearray):
        return bytes(value[:limit]).decode("utf-8", "replace")
    return str(value or "")[:limit]


def _ordered_headers(source):
    """Return ``(pairs, rejections, degraded, truncated)`` without combining fields."""
    degraded = False
    if isinstance(source, dict):
        raw = source.get("response_header_pairs")
        if raw is None:
            raw = source.get("header_pairs")
        if raw is None:
            raw = source.get("response_headers", source.get("headers"))
            if raw is None:
                response_keys = {"body", "text", "url", "final_url", "status", "status_code"}
                raw = {} if response_keys.intersection(source) else source
            degraded = isinstance(raw, dict)
        raw = list(islice(raw.items(), MAX_HEADERS + 1)) if isinstance(raw, dict) else raw
    else:
        raw = source
    if not isinstance(raw, (list, tuple)):
        return [], [{"index": None, "reason": "headers_not_ordered_pairs"}], degraded, False
    pairs, rejected = [], []
    truncated = len(raw) > MAX_HEADERS
    for index, item in enumerate(raw[:MAX_HEADERS]):
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            rejected.append({"index": index, "reason": "malformed_header_pair"})
            continue
        if not all(isinstance(part, (str, bytes, bytearray)) for part in item):
            rejected.append({"index": index, "reason": "header_pair_not_text"})
            continue
        name, value = _safe_text(item[0], MAX_HEADER_NAME + 1), _safe_text(item[1], MAX_HEADER_VALUE + 1)
        if len(name) > MAX_HEADER_NAME or not _HEADER_NAME.fullmatch(name):
            rejected.append({"index": index, "reason": "invalid_header_name"})
            continue
        if len(value.encode("utf-8", "replace")) > MAX_HEADER_VALUE:
            rejected.append({"index": index, "reason": "header_value_too_large"})
            continue
        if _has_control(value):
            rejected.append({"index": index, "reason": "header_value_contains_control"})
            continue
        pairs.append((name, value, index))
    return pairs, rejected[:MAX_FINDINGS], degraded, truncated


def _split_semicolons(value):
    """Split a Set-Cookie field on unquoted semicolons; None on broken quoting."""
    parts, current, quoted, escaped = [], [], False, False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quoted and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            current.append(char)
            continue
        if char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        return None
    parts.append("".join(current).strip())
    return parts


def _unquoted_comma(value):
    quoted = escaped = False
    for char in value:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            return True
    return False


def _unquoted_comma_count(value):
    quoted = escaped = False
    count = 0
    for char in value:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            count += 1
    return count


def _cookie_value(value):
    """Return ``(decoded_value, quoted)`` or None; never performs URL/base64 decoding."""
    value = value.strip()
    if len(value.encode("utf-8", "replace")) > MAX_COOKIE_VALUE or _has_control(value):
        return None
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            return None
        inner, out, escaped = value[1:-1], [], False
        for char in inner:
            if escaped:
                if char not in ('"', "\\"):
                    return None
                out.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"' or _has_control(char):
                return None
            else:
                out.append(char)
        if escaped:
            return None
        return "".join(out), True
    # RFC cookie-octet, deliberately strict for an unquoted value. Empty deletion values are valid.
    if any(not (ord(char) == 0x21 or 0x23 <= ord(char) <= 0x2B
               or 0x2D <= ord(char) <= 0x3A or 0x3C <= ord(char) <= 0x5B
               or 0x5D <= ord(char) <= 0x7E) for char in value):
        return None
    return value, False


def _origin(source_url):
    try:
        if not isinstance(source_url, str) or len(source_url) > 4096 or _has_control(source_url):
            return None
        parts = urllib.parse.urlsplit(source_url)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        parts.port  # force malformed ports to fail
        return {"scheme": parts.scheme.lower(), "host": parts.hostname.lower().rstrip("."),
                "path": parts.path or "/"}
    except (TypeError, ValueError):
        return None


def _default_path(path):
    if not path.startswith("/") or path.count("/") <= 1:
        return "/"
    result = path.rsplit("/", 1)[0]
    return result or "/"


def _domain_metadata(raw, origin):
    if raw is None:
        return {"present": False, "host_only": True,
                "effective": origin["host"] if origin else None,
                "assessment": "host_only" if origin else "host_only_origin_unknown"}
    value = raw.strip()
    normalized = value[1:] if value.startswith(".") else value
    normalized = normalized.lower()
    result = {"present": True, "host_only": False, "value": value[:253],
              "leading_dot_ignored": value.startswith("."), "effective": None,
              "public_suffix_check": "not_performed"}
    if (not normalized or len(normalized) > 253 or normalized.endswith(".") or ".." in normalized
            or _has_control(normalized) or any(char.isspace() for char in normalized)):
        result["assessment"] = "invalid_or_ambiguous"
        return result
    if any(ord(char) > 127 for char in normalized) or any(
            label.startswith("xn--") for label in normalized.split(".")):
        result["assessment"] = "declined_idn_ambiguity"
        return result
    if not re.fullmatch(r"[a-z0-9.-]+", normalized):
        result["assessment"] = "invalid_or_ambiguous"
        return result
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        result["assessment"] = "declined_ip_domain_ambiguity"
        return result
    if "." not in normalized:
        result["assessment"] = "declined_public_suffix_ambiguity"
        return result
    if origin is None:
        result["assessment"] = "declined_origin_unknown"
        return result
    host = origin["host"]
    if any(ord(char) > 127 for char in host) or any(label.startswith("xn--") for label in host.split(".")):
        result["assessment"] = "declined_idn_ambiguity"
        return result
    if host == normalized or host.endswith("." + normalized):
        result.update(assessment="syntactic_domain_match_psl_unchecked", effective=normalized)
    else:
        result["assessment"] = "syntactic_domain_mismatch"
    return result


def _parse_int(value):
    if value is None or not re.fullmatch(r"-?[0-9]{1,20}", value.strip()):
        return None
    try:
        return int(value)
    except (ValueError, OverflowError):
        return None


def _parse_expires(value):
    if value is None or len(value) > 200:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _b64decode(value, *, urlsafe=True):
    if not isinstance(value, str) or not value or len(value) > MAX_COOKIE_VALUE:
        return None
    matcher = _B64URL if urlsafe else _B64STD
    if not matcher.fullmatch(value):
        return None
    raw = value.encode("ascii")
    if len(raw) * 3 // 4 > MAX_DECODED:
        return None
    raw += b"=" * (-len(raw) % 4)
    try:
        decoded = (base64.urlsafe_b64decode(raw) if urlsafe else base64.b64decode(raw, validate=True))
    except (ValueError, binascii.Error):
        return None
    return decoded if len(decoded) <= MAX_DECODED else None


def _json_object(raw):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_DECODED:
        return None
    try:
        value = _security_json.loads(
            bytes(raw).decode("utf-8", "strict"),
            max_chars=MAX_DECODED,
            max_members=MAX_JSON_KEYS * 4,
            max_nodes=MAX_JSON_KEYS * 16,
            max_depth=32,
        )
    except (ValueError, UnicodeError, RecursionError):
        return None
    return value if isinstance(value, dict) and len(value) <= MAX_JSON_KEYS else None


def _keys(value):
    return sorted(str(key)[:80] for key in list(value)[:MAX_JSON_KEYS])


def _bounded_zlib(raw):
    try:
        dec = zlib.decompressobj()
        out = dec.decompress(raw, MAX_DECODED + 1)
        if len(out) > MAX_DECODED or dec.unconsumed_tail:
            return None
        out += dec.flush(MAX_DECODED + 1 - len(out))
        # zlib can expose the complete plaintext before it has received the
        # checksum/trailer.  Framework classification must not turn that
        # truncated stream (or a valid stream with concatenated junk) into a
        # structural session indicator.
        if (len(out) > MAX_DECODED or not dec.eof or dec.unconsumed_tail
                or dec.unused_data):
            return None
        return out
    except (ValueError, zlib.error):
        return None


def _indicator(kind, **metadata):
    out = {"kind": kind, "verified": False, "decoding": "unverified_structure_only"}
    out.update(metadata)
    return out


def _jwt_or_jwe(value):
    parts = value.split(".")
    if len(parts) not in (3, 5) or any(len(part) > MAX_COOKIE_VALUE for part in parts):
        return None
    if any(not _B64URL.fullmatch(part) for part in parts):
        return None
    header = _json_object(_b64decode(parts[0]) or b"")
    if not isinstance(header, dict) or not isinstance(header.get("alg"), str):
        return None
    if len(parts) == 5:
        if not isinstance(header.get("enc"), str):
            return None
        iv, ciphertext, tag = (_b64decode(parts[index]) for index in (2, 3, 4))
        if not iv or not ciphertext or not tag:
            return None
        return _indicator("jwe_compact", segments=5, alg=str(header["alg"])[:40],
                          enc=str(header["enc"])[:40], encrypted=True,
                          protected_header_keys=_keys(header))
    payload = _json_object(_b64decode(parts[1]) or b"")
    signature = _b64decode(parts[2]) if parts[2] else b""
    if str(header.get("alg") or "").lower() != "none" and not signature:
        return None
    return _indicator("jwt_jws", segments=3, alg=str(header["alg"])[:40],
                      typ=str(header.get("typ"))[:40] if header.get("typ") is not None else None,
                      signature_present=bool(parts[2]), payload_json=isinstance(payload, dict),
                      claim_keys=_keys(payload) if isinstance(payload, dict) else [])


def _paseto(value):
    parts = value.split(".")
    if len(parts) not in (3, 4) or parts[0] not in ("v1", "v2", "v3", "v4") \
            or parts[1] not in ("local", "public"):
        return None
    payload = _b64decode(parts[2])
    if payload is None or (len(parts) == 4 and (not parts[3] or _b64decode(parts[3]) is None)):
        return None
    return _indicator("paseto", version=parts[0], purpose=parts[1],
                      encrypted=parts[1] == "local", payload_bytes=len(payload),
                      footer_present=len(parts) >= 4 and bool(parts[3]))


def _flask(value):
    compressed = value.startswith(".")
    raw_value = value[1:] if compressed else value
    parts = raw_value.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    payload, stamp, signature = (_b64decode(part) for part in parts)
    if payload is None or stamp is None or signature is None or not 1 <= len(stamp) <= 8 \
            or len(signature) < 12:
        return None
    if compressed:
        payload = _bounded_zlib(payload)
    doc = _json_object(payload or b"")
    if doc is None:
        return None
    return _indicator("flask_itsdangerous", compressed=compressed, payload_keys=_keys(doc),
                      timestamp_bytes=len(stamp), signature_bytes=len(signature))


def _django(value):
    parts = value.rsplit(":", 2)
    if len(parts) != 3 or not _BASE62.fullmatch(parts[1]) or len(parts[2]) < 20 \
            or not _B64URL.fullmatch(parts[2]):
        return None
    payload_part = parts[0]
    compressed = payload_part.startswith(".")
    payload = _b64decode(payload_part[1:] if compressed else payload_part)
    if payload is None:
        return None
    if compressed:
        payload = _bounded_zlib(payload)
    doc = _json_object(payload or b"")
    if doc is None:
        return None
    return _indicator("django_signed_cookie", compressed=compressed, payload_keys=_keys(doc),
                      timestamp_chars=len(parts[1]), signature_chars=len(parts[2]))


def _express(value):
    try:
        decoded = urllib.parse.unquote(value)
    except Exception:
        return None
    if not decoded.startswith("s:") or "." not in decoded[2:]:
        return None
    payload, signature = decoded[2:].rsplit(".", 1)
    if not payload or len(payload) > MAX_COOKIE_VALUE or len(signature) < 16 \
            or not _B64URL.fullmatch(signature):
        return None
    return _indicator("express_cookie_signature", session_id_bytes=len(payload.encode("utf-8")),
                      signature_chars=len(signature), url_decoded=decoded != value)


def _rails(value):
    try:
        decoded = urllib.parse.unquote(value)
    except Exception:
        return None
    parts = decoded.split("--")
    if len(parts) not in (2, 3) or any(not part or len(part) > MAX_COOKIE_VALUE for part in parts):
        return None
    first = _b64decode(parts[0], urlsafe=False) or _b64decode(parts[0])
    if first is None:
        return None
    if len(parts) == 2:
        signature = parts[1]
        structured = first.startswith(b"\x04\x08") or _json_object(first) is not None
        if not structured or not ((_HEX.fullmatch(signature) and len(signature) >= 40)
                                  or (_B64ANY.fullmatch(signature) and len(signature) >= 20)):
            return None
        return _indicator("rails_signed_message", parts=2,
                          payload_format="ruby_marshal" if first.startswith(b"\x04\x08") else "json",
                          signature_chars=len(signature), url_decoded=decoded != value)
    if any(_b64decode(part, urlsafe=False) is None and _b64decode(part) is None for part in parts[1:]):
        return None
    return _indicator("rails_encrypted_message", parts=3, encrypted=True,
                      url_decoded=decoded != value)


def _laravel(value):
    raw = _b64decode(value, urlsafe=False) or _b64decode(value)
    doc = _json_object(raw or b"")
    if not isinstance(doc, dict) or not all(isinstance(doc.get(key), str) and doc[key]
                                             for key in ("iv", "value", "mac")):
        return None
    iv = _b64decode(doc["iv"], urlsafe=False) or _b64decode(doc["iv"])
    ciphertext = _b64decode(doc["value"], urlsafe=False) or _b64decode(doc["value"])
    tag = doc.get("tag")
    if not iv or not ciphertext or not _HEX.fullmatch(doc["mac"]) or len(doc["mac"]) < 32 \
            or (tag not in (None, "") and not (_b64decode(tag, urlsafe=False) or _b64decode(tag))):
        return None
    return _indicator("laravel_encrypted_cookie", encrypted=True,
                      envelope_keys=_keys(doc), iv_bytes=len(iv), ciphertext_bytes=len(ciphertext),
                      tag_present=isinstance(tag, str) and bool(tag))


def _aspnet(value):
    raw = _b64decode(value) or _b64decode(value, urlsafe=False)
    if raw is None or not raw.startswith(b"\x09\xf0\xc9\xf0"):
        return None
    return _indicator("aspnet_core_data_protection", encrypted_or_protected=True,
                      envelope_bytes=len(raw), magic="09f0c9f0")


def _macaroon(value):
    raw = _b64decode(value) or _b64decode(value, urlsafe=False)
    if raw is None:
        return None
    low = raw.lower()
    # V1 packetized/text macaroons contain both an identifier packet and a signature packet.
    if b"identifier" in low and b"signature" in low:
        return _indicator("macaroon_v1", serialized_bytes=len(raw))
    # V2 binary macaroons start with version 2 and carry multiple bounded field tags. This is a
    # deliberately weak indicator, never a verified format claim.
    if raw[:1] == b"\x02" and len(raw) >= 24 and raw.count(b"\x00") >= 2:
        return _indicator("macaroon_v2_candidate", serialized_bytes=len(raw), confidence="low")
    return None


def _entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def _envelopes(value):
    indicators = []
    for detector in (_jwt_or_jwe, _paseto, _express, _flask, _django,
                     _rails, _laravel, _aspnet, _macaroon):
        try:
            item = detector(value)
        except Exception:
            item = None
        if item and item["kind"] not in {row["kind"] for row in indicators}:
            indicators.append(item)
    if not indicators and len(value) >= 32 and _B64ANY.fullmatch(value) and _entropy(value) >= 3.5:
        indicators.append(_indicator("opaque_or_encrypted", confidence="low",
                                     encoded_chars=len(value), entropy=round(_entropy(value), 2)))
    return indicators[:12]


def _framework_hints(name):
    low = name.lower()
    hints = []
    checks = (
        (low in ("sessionid", "csrftoken"), "django"),
        (low == "_rails_session", "rails"),
        (low == "connect.sid", "express"),
        (low in ("laravel_session", "xsrf-token"), "laravel"),
        (low in (".aspxauth", "asp.net_sessionid") or low.startswith(".aspnetcore."), "aspnet"),
        (low == "session", "flask_or_generic"),
    )
    for matched, framework in checks:
        if matched:
            hints.append({"framework": framework, "basis": "name_only", "confidence": "hint_only"})
    return hints


def _parse_cookie(field, header_index, cookie_index, origin):
    if len(field.encode("utf-8", "replace")) > MAX_HEADER_VALUE or _has_control(field):
        return None, "malformed_or_oversized_set_cookie"
    parts = _split_semicolons(field)
    if not parts or not parts[0] or "=" not in parts[0]:
        return None, "malformed_cookie_pair"
    if len(parts) - 1 > MAX_ATTRIBUTES:
        return None, "too_many_cookie_attributes"
    name, raw_value = (piece.strip() for piece in parts[0].split("=", 1))
    if len(name) > MAX_COOKIE_NAME or not _COOKIE_NAME.fullmatch(name):
        return None, "invalid_cookie_name"
    if _unquoted_comma(parts[0]):
        return None, "ambiguous_combined_set_cookie"
    parsed_value = _cookie_value(raw_value)
    if parsed_value is None:
        return None, "invalid_cookie_value"
    value, quoted = parsed_value

    occurrences = defaultdict(list)
    unknown = []
    issues = []
    for raw_attr in parts[1:]:
        if not raw_attr:
            continue
        attr_name, sep, attr_value = raw_attr.partition("=")
        attr_name = attr_name.strip().lower()
        attr_value = attr_value.strip() if sep else None
        if len(attr_name) > MAX_ATTRIBUTE_NAME or not _COOKIE_NAME.fullmatch(attr_name):
            issues.append("invalid_attribute_name")
            continue
        comma_count = _unquoted_comma_count(raw_attr)
        if comma_count and attr_name != "expires":
            return None, "ambiguous_combined_set_cookie"
        if attr_name == "expires" and comma_count > 1:
            return None, "ambiguous_combined_set_cookie"
        if attr_value is not None and (len(attr_value) > 512 or _has_control(attr_value)):
            issues.append(f"invalid_{attr_name}_value")
            continue
        occurrences[attr_name].append(attr_value)
        if attr_name not in _KNOWN_ATTRS:
            unknown.append(attr_name)

    repeated = sorted(name for name, values in occurrences.items() if len(values) > 1)
    issues.extend("repeated_attribute:" + name for name in repeated)

    def unique(name):
        values = occurrences.get(name, [])
        return values[0] if len(values) == 1 else None

    flags = {}
    for attr in _FLAG_ATTRS:
        values = occurrences.get(attr, [])
        flags[attr] = any(value is None for value in values)
        if any(value is not None for value in values):
            issues.append(f"flag_has_value:{attr}")

    same_site_raw = unique("samesite")
    same_site = same_site_raw.lower() if isinstance(same_site_raw, str) else None
    if same_site is not None and same_site not in ("strict", "lax", "none"):
        issues.append("invalid_samesite")
        same_site = None
    path = unique("path")
    if path is not None and (not path.startswith("/") or _has_control(path)):
        issues.append("invalid_path")
        path = None
    if "domain" in repeated:
        domain = {"present": True, "host_only": False, "effective": None,
                  "assessment": "repeated_domain_ambiguous",
                  "public_suffix_check": "not_performed"}
    else:
        domain = _domain_metadata(unique("domain"), origin)
    max_age_raw = unique("max-age")
    max_age = _parse_int(max_age_raw)
    if max_age_raw is not None and max_age is None:
        issues.append("invalid_max_age")
    expires_raw = unique("expires")
    expires = _parse_expires(expires_raw)
    if expires_raw is not None and expires is None:
        if re.search(r",\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+\s*=", expires_raw):
            return None, "ambiguous_combined_set_cookie"
        issues.append("invalid_expires")

    effective_path = (None if "path" in repeated else
                      path or (_default_path(origin["path"]) if origin else None))
    now = datetime.now(timezone.utc)
    lifetime_ambiguous = "max-age" in repeated or "expires" in repeated
    if lifetime_ambiguous:
        deletion = False
        deletion_assessment = "ambiguous_repeated_lifetime_attribute"
    elif max_age is not None:  # Max-Age takes precedence over Expires.
        deletion = max_age <= 0
        deletion_assessment = "delete" if deletion else "retain"
    elif expires is not None:
        deletion = expires <= now
        deletion_assessment = "delete" if deletion else "retain"
    else:
        deletion = False
        deletion_assessment = "retain_empty_value" if value == "" else "retain"

    prefix = None
    violations = []
    if name.startswith("__Host-"):
        prefix = "__Host-"
        if not flags["secure"]:
            violations.append("__Host_requires_Secure")
        if occurrences.get("domain"):
            violations.append("__Host_forbids_Domain")
        if path != "/":
            violations.append("__Host_requires_Path_root")
        if origin and origin["scheme"] != "https":
            violations.append("__Host_requires_secure_origin")
    elif name.startswith("__Secure-"):
        prefix = "__Secure-"
        if not flags["secure"]:
            violations.append("__Secure_requires_Secure")
        if origin and origin["scheme"] != "https":
            violations.append("__Secure_requires_secure_origin")
    elif name.lower().startswith(("__host-", "__secure-")):
        prefix = "case_mismatch_lookalike"
    if same_site == "none" and not flags["secure"]:
        violations.append("SameSite_None_without_Secure")
    if flags["partitioned"] and not flags["secure"]:
        violations.append("Partitioned_without_Secure")
    if flags["secure"] and origin and origin["scheme"] != "https":
        violations.append("Secure_set_from_non_https_origin")

    encoded_kind = "empty" if value == "" else (
        "hex" if len(value) >= 16 and _HEX.fullmatch(value) else
        "base64_like" if len(value) >= 16 and _B64ANY.fullmatch(value) else "opaque_text")
    public = {
        "index": cookie_index,
        "header_index": header_index,
        "name": name,
        "value_metadata": {"length": len(value.encode("utf-8", "surrogatepass")),
                           "sha256_prefix": _fingerprint(value), "quoted": quoted,
                           "shape": encoded_kind},
        "attributes": {
            "secure": flags["secure"], "httponly": flags["httponly"],
            "partitioned": flags["partitioned"], "samesite": same_site,
            "domain": domain, "path": path, "effective_path": effective_path,
            "max_age": max_age,
            "expires": expires.isoformat() if expires is not None else None,
            "unknown_names": sorted(set(unknown)),
        },
        "repeated_attributes": repeated,
        "attribute_issues": sorted(set(issues)),
        "prefix": prefix,
        "prefix_violations": sorted(set(violations)),
        "deletion": deletion, "deletion_assessment": deletion_assessment,
        "framework_hints": _framework_hints(name),
        "envelopes": _envelopes(value),
    }
    scope = (domain.get("effective"), effective_path) if domain.get("effective") and effective_path else None
    internal = {"value": value, "fingerprint": _fingerprint(value), "scope": scope,
                "domain_present": domain["present"], "deletion": deletion}
    return (public, internal), None


class _CSRFHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tokens = []

    def handle_starttag(self, tag, attrs):
        if len(self.tokens) >= MAX_CSRF_TOKENS or len(attrs) > 64:
            return
        grouped = defaultdict(list)
        for name, value in attrs:
            if isinstance(name, str):
                grouped[name.lower()].append(value)
        if any(len(values) > 1 for values in grouped.values()):
            return
        if tag.lower() == "input":
            name = grouped.get("name", [None])[0]
            value = grouped.get("value", [None])[0]
            if isinstance(name, str) and _CSRF_NAME.search(name) and isinstance(value, str):
                input_type = grouped.get("type", [None])[0]
                kind = ("html_hidden_input" if isinstance(input_type, str)
                        and input_type.lower() == "hidden" else "html_input")
                self.tokens.append((value, kind, name[:120], "html_entity_decoded"))
        elif tag.lower() == "meta":
            name = grouped.get("name", grouped.get("property", [None]))[0]
            value = grouped.get("content", [None])[0]
            if isinstance(name, str) and _CSRF_NAME.search(name) and isinstance(value, str):
                self.tokens.append((value, "html_meta", name[:120], "html_entity_decoded"))


_JS_CSRF = re.compile(
    r"(?is)(?:^|[^A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$.-]{0,80}(?:csrf|xsrf)[A-Za-z0-9_$.-]{0,80})"
    r"\s*(?::|=)\s*(['\"])(.{8,4096}?)\2")
_JSON_CSRF = re.compile(
    r"(?is)(?:^|[,{])\s*(['\"])([^'\"]{0,80}(?:csrf|xsrf)[^'\"]{0,80})\1"
    r"\s*:\s*(['\"])(.{8,4096}?)\3")


def _valid_token(value):
    return (isinstance(value, str) and 8 <= len(value.encode("utf-8", "replace")) <= MAX_TOKEN
            and not _has_control(value) and value.lower() not in ("csrf", "xsrf", "token", "changeme")
            and "{{" not in value and "}}" not in value)


def _csrf_inventory(cookies, pairs, body, should_stop=None):
    tokens = []
    for public, internal in cookies:
        if callable(should_stop) and should_stop():
            break
        if _CSRF_NAME.search(public["name"]) and _valid_token(internal["value"]):
            tokens.append((internal["value"], "cookie", public["name"], "exact"))
    for name, value, _ in pairs:
        if callable(should_stop) and should_stop():
            break
        if _CSRF_NAME.search(name) and _valid_token(value):
            tokens.append((value, "response_header", name, "exact"))
    parser = _CSRFHTML()
    if not (callable(should_stop) and should_stop()):
        try:
            parser.feed(body)
            parser.close()
            tokens.extend(parser.tokens)
        except Exception:
            pass
    for match in _JS_CSRF.finditer(body[:MAX_BODY]):
        if callable(should_stop) and should_stop():
            break
        tokens.append((match.group(3), "javascript_literal", match.group(1)[:120], "static_literal"))
    for match in _JSON_CSRF.finditer(body[:MAX_BODY]):
        if callable(should_stop) and should_stop():
            break
        tokens.append((match.group(4), "json_literal", match.group(2)[:120], "static_literal"))

    tokens = [row for row in tokens if _valid_token(row[0])][:MAX_CSRF_TOKENS]
    grouped = {}
    for value, location, name, decoding in tokens:
        key = _fingerprint(value)
        item = grouped.setdefault(key, {"fingerprint": key,
                                        "length": len(value.encode("utf-8", "replace")),
                                        "locations": [], "_value": value})
        loc = {"kind": location, "name": name, "decoding": decoding}
        if loc not in item["locations"]:
            item["locations"].append(loc)

    bindings = []
    cookie_rows = [row for row in tokens if row[1] == "cookie"]
    noncookie_rows = [row for row in tokens if row[1] != "cookie"]
    for cookie_value, _, cookie_name, _ in cookie_rows:
        for token_value, location, token_name, _ in noncookie_rows:
            comparison = None
            if cookie_value == token_value:
                comparison = "exact"
            elif "%" in cookie_value:
                try:
                    if urllib.parse.unquote(cookie_value) == token_value:
                        comparison = "url_decoded_unverified"
                except Exception:
                    pass
            if comparison:
                row = {"kind": "double_submit_indicator", "cookie_name": cookie_name,
                       "token_location": location, "token_name": token_name,
                       "fingerprint": _fingerprint(token_value), "comparison": comparison,
                       "verified_binding": False}
                if row not in bindings:
                    bindings.append(row)

    public_tokens = []
    for item in grouped.values():
        item = dict(item)
        item.pop("_value", None)
        item["locations"] = item["locations"][:16]
        public_tokens.append(item)
    return {"tokens": public_tokens[:MAX_CSRF_TOKENS],
            "bindings": bindings[:MAX_FINDINGS],
            "binding_note": "co-location or equality is an indicator only; no server-side binding was verified"}


def _ambiguities(cookies):
    by_name = defaultdict(list)
    by_value = defaultdict(list)
    for public, internal in cookies:
        by_name[public["name"]].append((public, internal))
        by_value[internal["fingerprint"]].append((public, internal))
    names = []
    for name, rows in by_name.items():
        if len(rows) < 2:
            continue
        scopes = [internal["scope"] for _, internal in rows]
        domains = [public["attributes"]["domain"] for public, _ in rows]
        paths = [public["attributes"]["effective_path"] for public, _ in rows]
        relations = []
        if None in scopes:
            relations.append("scope_undetermined")
        if len(set(scope for scope in scopes if scope is not None)) < len([scope for scope in scopes if scope is not None]):
            relations.append("same_scope_overwrite")
        if len(set(path for path in paths if path is not None)) > 1:
            relations.append("path_shadowing")
        effective_domains = [domain.get("effective") for domain in domains]
        if len(set(domain for domain in effective_domains if domain)) > 1 \
                or len({domain.get("present") for domain in domains}) > 1:
            relations.append("domain_shadowing_or_host_only_ambiguity")
        names.append({"name": name, "cookie_indices": [public["index"] for public, _ in rows],
                      "same_value": len({internal["fingerprint"] for _, internal in rows}) == 1,
                      "active_and_deletion_mixed": len({internal["deletion"] for _, internal in rows}) > 1,
                      "relations": relations or ["duplicate_name"]})
    values = []
    for fingerprint, rows in by_value.items():
        if len(rows) > 1:
            values.append({"fingerprint": fingerprint,
                           "cookie_indices": [public["index"] for public, _ in rows],
                           "names": [public["name"] for public, _ in rows]})
    return names[:MAX_FINDINGS], values[:MAX_FINDINGS]


def analyze(header_pairs_or_response, body=None, source_url=None, *, deadline=None, stop=None):
    """Inventory already-fetched session/cookie evidence; never performs an action."""
    should_stop = lambda: _halted(deadline, stop)
    stopped_early = should_stop()
    if stopped_early:
        header_pairs_or_response = []
        body = ""
        source_url = None
    response = header_pairs_or_response if isinstance(header_pairs_or_response, dict) else None
    pairs, header_rejections, degraded, headers_truncated = _ordered_headers(header_pairs_or_response)
    if body is None and response is not None:
        body = response.get("body", response.get("text", ""))
    if source_url is None and response is not None:
        source_url = response.get("final_url") or response.get("url")
    if not isinstance(body, (str, bytes, bytearray, type(None))):
        body_text, body_rejected = "", True
        body_truncated = False
    else:
        raw_body = (body.encode("utf-8", "replace") if isinstance(body, str)
                    else bytes(body or b""))
        body_truncated = len(raw_body) > MAX_BODY
        body_text = raw_body[:MAX_BODY].decode("utf-8", "replace")
        body_rejected = False
    origin = _origin(source_url)

    cookies = []
    rejected = []
    set_cookie_fields = 0
    for name, value, header_index in pairs:
        if should_stop():
            stopped_early = True
            break
        if name.lower() != "set-cookie":
            continue
        set_cookie_fields += 1
        if len(cookies) >= MAX_COOKIES:
            rejected.append({"header_index": header_index, "reason": "cookie_limit_reached"})
            continue
        parsed, error = _parse_cookie(value, header_index, len(cookies), origin)
        if error:
            rejected.append({"header_index": header_index, "reason": error})
        else:
            cookies.append(parsed)

    duplicate_names, duplicate_values = _ambiguities(cookies)
    csrf = _csrf_inventory(cookies, pairs, body_text, should_stop=should_stop)
    stopped_early |= should_stop()
    public_cookies = [public for public, _ in cookies]
    envelope_count = sum(len(cookie["envelopes"]) for cookie in public_cookies)
    return {
        "offline_only": True,
        "stopped_early": stopped_early,
        "network_requests": 0,
        "credentials_forged_or_replayed": False,
        "proof": None,
        "headers": {"accepted_pairs": len(pairs), "set_cookie_fields": set_cookie_fields,
                    "ordered_pairs_degraded": degraded, "truncated": headers_truncated,
                    "rejected": header_rejections},
        "body": {"inspected_bytes": len(body_text.encode("utf-8", "replace")),
                 "truncated": body_truncated, "rejected_type": body_rejected},
        "cookies": public_cookies,
        "rejected_cookies": rejected[:MAX_FINDINGS],
        "duplicate_names": duplicate_names,
        "duplicate_values": duplicate_values,
        "csrf": csrf,
        "summary": {"cookies": len(public_cookies), "deletions": sum(c["deletion"] for c in public_cookies),
                    "prefix_violations": sum(bool(c["prefix_violations"]) for c in public_cookies),
                    "envelope_indicators": envelope_count,
                    "csrf_tokens": len(csrf["tokens"])},
        "notes": [
            "all decoded envelope metadata is unverified; no signature or server-side binding was checked",
            "cookie and CSRF values are omitted; fingerprints are for within-report correlation only",
            "public-suffix and IDN validity are deliberately not inferred without an authoritative PSL/IDNA policy",
        ],
    }


def analyze_response(response, source_url=None, *, deadline=None, stop=None):
    """Convenience wrapper for a WebClient-style response dictionary."""
    return analyze(response, source_url=source_url, deadline=deadline, stop=stop)


__all__ = ["analyze", "analyze_response"]
