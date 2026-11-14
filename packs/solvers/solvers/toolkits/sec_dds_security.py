#!/usr/bin/env python3
"""Offline DDS-Security wire-envelope and policy-document analyzer.

The wire parser accepts either a complete DDSI-RTPS message or a bare sequence of
RTPS submessages.  It understands the DDS-Security 1.2 SEC_BODY, SEC_PREFIX,
SEC_POSTFIX, SRTPS_PREFIX, and SRTPS_POSTFIX layouts.  It only describes crypto
metadata and authentication tags: it never decrypts, verifies, transmits, or
constructs traffic.

The document parser accepts supplied governance/permissions XML or its required
S/MIME multipart/signed wrapper.  It performs bounded structural and policy linting
without resolving a schema or external entity.  Signature presence is distinct
from verification; this module deliberately has no trust-store interface and always
reports cryptographic verification as ``not-performed``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


MAX_INPUT = 16 * 1024 * 1024
MAX_XML = 4 * 1024 * 1024
MAX_SUBMESSAGES = 4096
MAX_RECEIVER_MACS = 4096
MAX_XML_NODES = 20_000
MAX_XML_DEPTH = 64
MAX_NAME = 512
MAX_TEXT = 64 * 1024
MAX_RULES = 4096
MAX_PREVIEW = 256


class SecDDSSecurityError(ValueError):
    """Malformed, unsupported, ambiguous, or over-limit supplied evidence."""


SECURE_IDS = {
    0x30: "SEC_BODY",
    0x31: "SEC_PREFIX",
    0x32: "SEC_POSTFIX",
    0x33: "SRTPS_PREFIX",
    0x34: "SRTPS_POSTFIX",
}

RTPS_IDS = {
    0x00: "RTPS_HE",
    0x01: "PAD",
    0x06: "ACKNACK",
    0x07: "HEARTBEAT",
    0x08: "GAP",
    0x09: "INFO_TS",
    0x0C: "INFO_SRC",
    0x0D: "INFO_REPLY_IP4",
    0x0E: "INFO_DST",
    0x0F: "INFO_REPLY",
    0x12: "NACK_FRAG",
    0x13: "HEARTBEAT_FRAG",
    0x15: "DATA",
    0x16: "DATA_FRAG",
    **SECURE_IDS,
}

ALGORITHMS = {
    0: "NONE",
    1: "AES128_GMAC",
    2: "AES128_GCM",
    3: "AES256_GMAC",
    4: "AES256_GCM",
}

PROTECTION_KINDS = {
    "NONE",
    "SIGN",
    "ENCRYPT",
    "SIGN_WITH_ORIGIN_AUTHENTICATION",
    "ENCRYPT_WITH_ORIGIN_AUTHENTICATION",
}
BASIC_PROTECTION_KINDS = {"NONE", "SIGN", "ENCRYPT"}

_FORBIDDEN_XML = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_XML_DECL_ENCODING = re.compile(r"<\?xml[^>]*\bencoding\s*=\s*['\"]([^'\"]+)", re.IGNORECASE)
_CMS_SIGNED_DATA_OID = bytes.fromhex("06092a864886f70d010702")


def _blob(value: Any, *, limit: int | None = None, label: str = "input") -> bytes:
    if limit is None:
        limit = MAX_INPUT
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecDDSSecurityError(f"{label} must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > limit:
            raise SecDDSSecurityError(f"{label} exceeds size limit")
        data = bytes(value)
    except SecDDSSecurityError:
        raise
    except Exception as exc:
        raise SecDDSSecurityError(f"cannot copy {label}") from exc
    if not data:
        raise SecDDSSecurityError(f"{label} is empty")
    return data


def _need(data: bytes, offset: int, length: int, label: str) -> None:
    if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
        raise SecDDSSecurityError(f"truncated {label}")


def _preview(data: bytes) -> dict[str, Any]:
    shown = data[:MAX_PREVIEW]
    return {
        "length": len(data),
        "hex": shown.hex(),
        "ascii": "".join(chr(octet) if 0x20 <= octet <= 0x7E else "." for octet in shown),
        "truncated": len(data) > len(shown),
    }


def _finding(kind: str, severity: str, detail: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "detail": detail, **fields}


def _crypto_header(body: bytes) -> dict[str, Any]:
    _need(body, 0, 20, "DDS-Security CryptoHeader")
    revision = body[:3]
    algorithm_id = body[3]
    key_id = body[4:8]
    session_id = body[8:12]
    suffix = body[12:20]
    return {
        "transformation_kind_hex": body[:4].hex(),
        "key_revision": int.from_bytes(revision, "big"),
        "key_revision_hex": revision.hex(),
        "algorithm_id": algorithm_id,
        "algorithm": ALGORITHMS.get(algorithm_id, "UNKNOWN"),
        "transformation_key_id": int.from_bytes(key_id, "big"),
        "transformation_key_id_hex": key_id.hex(),
        "session_id": int.from_bytes(session_id, "big"),
        "session_id_hex": session_id.hex(),
        "initialization_vector_suffix_hex": suffix.hex(),
        "initialization_vector_hex": (session_id + suffix).hex(),
        "serialization_endianness": "big",
        "plugin_extra_hex": body[20:].hex(),
    }


def _crypto_content(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "DDS-Security CryptoContent length")
    size = int.from_bytes(body[:4], "big")
    if size > MAX_INPUT:
        raise SecDDSSecurityError("CryptoContent length exceeds limit")
    if size != len(body) - 4:
        raise SecDDSSecurityError("CryptoContent length does not match SEC_BODY")
    content = body[4:]
    return {
        "content_length": size,
        "content": _preview(content),
        "serialization_endianness": "big",
    }


def _crypto_footer(body: bytes) -> dict[str, Any]:
    _need(body, 0, 20, "DDS-Security CryptoFooter")
    count = int.from_bytes(body[16:20], "big")
    if count > MAX_RECEIVER_MACS:
        raise SecDDSSecurityError("receiver-specific MAC count exceeds limit")
    expected = 20 + count * 20
    if expected != len(body):
        raise SecDDSSecurityError("CryptoFooter receiver count does not match length")
    receivers = []
    offset = 20
    for _ in range(count):
        key_id = body[offset:offset + 4]
        mac = body[offset + 4:offset + 20]
        receivers.append({
            "receiver_mac_key_id": int.from_bytes(key_id, "big"),
            "receiver_mac_key_id_hex": key_id.hex(),
            "receiver_mac_hex": mac.hex(),
        })
        offset += 20
    return {
        "common_mac_hex": body[:16].hex(),
        "receiver_specific_mac_count": count,
        "receiver_specific_macs": receivers,
        "serialization_endianness": "big",
        "verification": "not-performed",
    }


def _decode_secure_submessage(kind: int, body: bytes) -> dict[str, Any]:
    if kind in (0x31, 0x33):
        return {"crypto_header": _crypto_header(body)}
    if kind == 0x30:
        return {"crypto_content": _crypto_content(body)}
    if kind in (0x32, 0x34):
        return {"crypto_footer": _crypto_footer(body)}
    return {"opaque": _preview(body)}


def _walk_submessages(data: bytes, start: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    offset = start
    while offset < len(data):
        if len(rows) >= MAX_SUBMESSAGES:
            raise SecDDSSecurityError("RTPS submessage count exceeds limit")
        if offset % 4:
            raise SecDDSSecurityError("RTPS submessage header is not 32-bit aligned")
        _need(data, offset, 4, "RTPS submessage header")
        kind = data[offset]
        flags = data[offset + 1]
        endian = "little" if flags & 1 else "big"
        declared = int.from_bytes(data[offset + 2:offset + 4], endian)
        content_start = offset + 4
        if declared:
            end = content_start + declared
            if end > len(data):
                raise SecDDSSecurityError("RTPS submessage length exceeds supplied message")
        elif kind in (0x01, 0x09):
            end = content_start
        else:
            end = len(data)
        body = data[content_start:end]
        row: dict[str, Any] = {
            "offset": offset,
            "id": kind,
            "id_hex": f"0x{kind:02x}",
            "name": RTPS_IDS.get(kind, "VENDOR_SPECIFIC" if kind >= 0x80 else "UNKNOWN"),
            "flags": flags,
            "endianness": endian,
            "declared_length": declared,
            "body_length": len(body),
        }
        if kind == 0x33:
            row["additional_authenticated_data"] = bool(flags & 0x02)
            row["pre_shared_key"] = bool(flags & 0x04)
            if flags & ~0x07:
                findings.append(_finding("reserved-secure-flags", "medium",
                    "SRTPS_PREFIX has reserved flag bits set", offset=offset, flags=flags))
        elif kind in SECURE_IDS and flags & ~0x01:
            findings.append(_finding("reserved-secure-flags", "medium",
                "secure submessage has reserved flag bits set", offset=offset, flags=flags))
        if kind in SECURE_IDS:
            row.update(_decode_secure_submessage(kind, body))
            header = row.get("crypto_header")
            if header and header["algorithm"] == "UNKNOWN":
                findings.append(_finding("unknown-crypto-algorithm", "medium",
                    "CryptoHeader uses an unknown or plugin-specific algorithm",
                    offset=offset, algorithm_id=header["algorithm_id"]))
            if header and header["algorithm_id"] == 0:
                findings.append(_finding("none-crypto-algorithm", "high",
                    "secure prefix selects the NONE transformation", offset=offset))
        else:
            row["opaque"] = _preview(body)
        rows.append(row)
        if end == len(data):
            offset = end
            break
        if end % 4:
            raise SecDDSSecurityError("next RTPS submessage would be unaligned")
        offset = end
    if not rows:
        raise SecDDSSecurityError("RTPS message has no submessages")
    return rows, findings


def _sequence_findings(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    sequences: list[dict[str, Any]] = []
    active: dict[str, Any] | None = None
    for index, row in enumerate(rows):
        kind = row["id"]
        if kind in (0x31, 0x33):
            if active is not None:
                findings.append(_finding("nested-secure-prefix", "high",
                    "a secure prefix appears before the previous envelope closes",
                    offset=row["offset"], previous_offset=active["offset"]))
            active = {
                "scope": "rtps-message" if kind == 0x33 else "endpoint-submessage",
                "prefix_index": index,
                "offset": row["offset"],
                "algorithm_id": row["crypto_header"]["algorithm_id"],
                "body_indexes": [],
                "protected_indexes": [],
            }
            continue
        if kind in (0x32, 0x34):
            expected = 0x34 if active and active["scope"] == "rtps-message" else 0x32
            if active is None:
                findings.append(_finding("orphan-secure-postfix", "high",
                    "secure postfix has no preceding prefix", offset=row["offset"]))
                continue
            if kind != expected:
                findings.append(_finding("mismatched-secure-postfix", "high",
                    "secure postfix scope does not match its prefix", offset=row["offset"]))
            active["postfix_index"] = index
            active["postfix_offset"] = row["offset"]
            algorithm = active["algorithm_id"]
            encrypted = algorithm in (2, 4)
            authenticated_only = algorithm in (1, 3)
            active["mode"] = "encrypt" if encrypted else "sign" if authenticated_only else "unknown"
            if encrypted and not active["body_indexes"]:
                findings.append(_finding("missing-secure-body", "high",
                    "GCM envelope has no SEC_BODY", offset=active["offset"]))
            if authenticated_only and active["body_indexes"]:
                findings.append(_finding("unexpected-secure-body", "high",
                    "GMAC authentication-only envelope contains SEC_BODY", offset=active["offset"]))
            if len(active["body_indexes"]) > 1:
                findings.append(_finding("multiple-secure-bodies", "high",
                    "one secure envelope contains multiple SEC_BODY records", offset=active["offset"]))
            sequences.append(active)
            active = None
            continue
        if kind == 0x30:
            if active is None:
                findings.append(_finding("orphan-secure-body", "high",
                    "SEC_BODY has no active secure prefix", offset=row["offset"]))
            else:
                active["body_indexes"].append(index)
        elif active is not None:
            active["protected_indexes"].append(index)
    if active is not None:
        findings.append(_finding("unclosed-secure-envelope", "high",
            "secure prefix has no matching postfix", offset=active["offset"]))
    return sequences, findings


def _parse_secure_rtps(data: bytes, framing: str) -> dict[str, Any]:
    if framing == "auto":
        framing = "rtps" if data.startswith(b"RTPS") else "submessages"
    if framing not in {"rtps", "submessages"}:
        raise SecDDSSecurityError("framing must be auto, rtps, or submessages")
    header = None
    start = 0
    if framing == "rtps":
        _need(data, 0, 20, "RTPS header")
        if data[:4] != b"RTPS":
            raise SecDDSSecurityError("RTPS magic is missing")
        if data[4] != 2:
            raise SecDDSSecurityError("only RTPS major version 2 is supported")
        header = {
            "magic": "RTPS",
            "protocol_version": f"{data[4]}.{data[5]}",
            "protocol_major": data[4],
            "protocol_minor": data[5],
            "vendor_id_hex": data[6:8].hex(),
            "guid_prefix_hex": data[8:20].hex(),
        }
        start = 20
    rows, findings = _walk_submessages(data, start)
    sequences, relationship_findings = _sequence_findings(rows)
    findings.extend(relationship_findings)
    secure_count = sum(row["id"] in SECURE_IDS for row in rows)
    if not secure_count:
        findings.append(_finding("no-dds-security-submessages", "medium",
            "RTPS evidence contains no DDS-Security crypto submessages"))
    return {
        "format": "DDS-Security RTPS",
        "framing": framing,
        "size": len(data),
        "rtps_header": header,
        "submessages": rows,
        "secure_submessage_count": secure_count,
        "secure_sequences": sequences,
        "findings": findings,
        "mac_verification": "not-performed",
        "mac_verification_reason": "no cryptographic keys were supplied",
    }


def parse_secure_rtps(data: bytes | bytearray | memoryview, *, framing: str = "auto") -> dict[str, Any]:
    """Parse a complete RTPS message or bare aligned submessage stream.

    ``framing='auto'`` selects a complete message only when the supplied bytes begin
    with ``RTPS``; otherwise offset zero is treated as the first submessage header.
    Every ordinary failure is normalized to :class:`SecDDSSecurityError`.
    """
    try:
        if not isinstance(framing, str):
            raise SecDDSSecurityError("framing must be text")
        return _parse_secure_rtps(_blob(data, label="secure RTPS evidence"), framing)
    except SecDDSSecurityError:
        raise
    except Exception as exc:
        raise SecDDSSecurityError("malformed secure RTPS evidence") from exc


def _xml_text(raw: bytes) -> str:
    if len(raw) > MAX_XML:
        raise SecDDSSecurityError("DDS security XML exceeds size limit")
    encoding = "utf-8-sig"
    allowed = {"utf-8", "utf8", "us-ascii", "ascii"}
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        raise SecDDSSecurityError("UTF-32 XML is unsupported")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
        allowed = {"utf-16", "utf16", "utf-16le", "utf16le", "utf-16be", "utf16be"}
    elif raw.startswith(b"<\x00?\x00"):
        encoding = "utf-16-le"
        allowed = {"utf-16", "utf16", "utf-16le", "utf16le"}
    elif raw.startswith(b"\x00<\x00?"):
        encoding = "utf-16-be"
        allowed = {"utf-16", "utf16", "utf-16be", "utf16be"}
    try:
        text = raw.decode(encoding, "strict")
    except (LookupError, UnicodeDecodeError) as exc:
        raise SecDDSSecurityError("DDS security XML encoding is invalid") from exc
    if "\x00" in text:
        raise SecDDSSecurityError("DDS security XML contains NUL characters")
    declaration = _XML_DECL_ENCODING.search(text[:1024])
    if declaration and declaration.group(1).strip().lower() not in allowed:
        raise SecDDSSecurityError("XML declaration conflicts with byte encoding")
    if _FORBIDDEN_XML.search(text):
        raise SecDDSSecurityError("DTD and entity declarations are forbidden")
    return text


class _BoundedTree(ET.TreeBuilder):
    def __init__(self) -> None:
        super().__init__()
        self.depth = 0
        self.count = 0

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.depth += 1
        self.count += 1
        if self.depth > MAX_XML_DEPTH or self.count > MAX_XML_NODES:
            raise SecDDSSecurityError("XML depth/node limit exceeded")
        if len(tag) > MAX_NAME or any(len(key) > MAX_NAME or len(value) > MAX_TEXT for key, value in attrs.items()):
            raise SecDDSSecurityError("XML name/attribute limit exceeded")
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        self.depth -= 1
        return super().end(tag)

    def data(self, data: str) -> None:
        if len(data) > MAX_TEXT:
            raise SecDDSSecurityError("XML text node exceeds limit")
        super().data(data)

    def doctype(self, name: str, pubid: str, system: str) -> None:
        raise SecDDSSecurityError("DTD and entity declarations are forbidden")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(element: ET.Element, name: str | None = None) -> list[ET.Element]:
    rows = list(element)
    return rows if name is None else [row for row in rows if _local(row.tag) == name]


def _one(element: ET.Element, name: str, *, required: bool = False) -> ET.Element | None:
    rows = _children(element, name)
    if len(rows) > 1:
        raise SecDDSSecurityError(f"duplicate {name} element")
    if required and not rows:
        raise SecDDSSecurityError(f"missing {name} element")
    return rows[0] if rows else None


def _text(element: ET.Element | None, label: str, *, required: bool = False) -> str | None:
    if element is None:
        if required:
            raise SecDDSSecurityError(f"missing {label}")
        return None
    value = (element.text or "").strip()
    if required and not value:
        raise SecDDSSecurityError(f"empty {label}")
    if len(value) > MAX_TEXT:
        raise SecDDSSecurityError(f"{label} exceeds text limit")
    return value


def _boolean(element: ET.Element | None, label: str, *, required: bool = False) -> bool | None:
    value = _text(element, label, required=required)
    if value is None:
        return None
    lowered = value.lower()
    if lowered not in {"true", "false"}:
        raise SecDDSSecurityError(f"invalid {label} boolean")
    return lowered == "true"


def _integer(element: ET.Element, label: str) -> int:
    value = _text(element, label, required=True)
    assert value is not None
    if not value.isascii() or not value.isdigit():
        raise SecDDSSecurityError(f"invalid {label} integer")
    number = int(value)
    if number > 0xFFFFFFFF:
        raise SecDDSSecurityError(f"{label} integer exceeds limit")
    return number


def _domains(element: ET.Element) -> list[dict[str, int]]:
    result: list[dict[str, int]] = []
    for child in _children(element):
        kind = _local(child.tag)
        if kind == "id":
            value = _integer(child, "domain id")
            result.append({"min": value, "max": value})
        elif kind == "id_range":
            minimum = _integer(_one(child, "min", required=True), "domain range minimum")  # type: ignore[arg-type]
            maximum_el = _one(child, "max")
            maximum = _integer(maximum_el, "domain range maximum") if maximum_el is not None else 0xFFFFFFFF
            if maximum < minimum:
                raise SecDDSSecurityError("domain range maximum precedes minimum")
            result.append({"min": minimum, "max": maximum})
        else:
            raise SecDDSSecurityError(f"unsupported domains child {kind}")
        if len(result) > MAX_RULES:
            raise SecDDSSecurityError("domain selector count exceeds limit")
    if not result:
        raise SecDDSSecurityError("domains selector is empty")
    return result


def _protection(element: ET.Element | None, label: str, *, basic: bool = False,
                required: bool = False) -> str | None:
    value = _text(element, label, required=required)
    if value is None:
        return None
    allowed = BASIC_PROTECTION_KINDS if basic else PROTECTION_KINDS
    if value not in allowed:
        raise SecDDSSecurityError(f"invalid {label} value")
    return value


def _governance(root: ET.Element) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    access = _one(root, "domain_access_rules", required=True)
    assert access is not None
    rules = _children(access, "domain_rule")
    if not rules or len(rules) > MAX_RULES:
        raise SecDDSSecurityError("governance domain-rule count is invalid")
    out_rules: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for index, rule in enumerate(rules):
        domains_el = _one(rule, "domains", required=True)
        assert domains_el is not None
        row: dict[str, Any] = {
            "index": index,
            "domains": _domains(domains_el),
            "allow_unauthenticated_participants": _boolean(
                _one(rule, "allow_unauthenticated_participants"),
                "allow_unauthenticated_participants", required=True),
            "enable_join_access_control": _boolean(
                _one(rule, "enable_join_access_control"), "enable_join_access_control", required=True),
            "enable_key_revision": _boolean(_one(rule, "enable_key_revision"), "enable_key_revision"),
            "discovery_protection_kind": _protection(
                _one(rule, "discovery_protection_kind"), "discovery_protection_kind", required=True),
            "liveliness_protection_kind": _protection(
                _one(rule, "liveliness_protection_kind"), "liveliness_protection_kind", required=True),
            "rtps_protection_kind": _protection(
                _one(rule, "rtps_protection_kind"), "rtps_protection_kind", required=True),
            "rtps_psk_protection_kind": _protection(
                _one(rule, "rtps_psk_protection_kind"), "rtps_psk_protection_kind", basic=True),
            "topic_rules": [],
        }
        if row["allow_unauthenticated_participants"]:
            findings.append(_finding("unauthenticated-participants", "high",
                "governance allows unauthenticated participants", rule=index))
        if row["enable_join_access_control"] is False:
            findings.append(_finding("join-access-control-disabled", "high",
                "governance disables join access control", rule=index))
        if row["enable_key_revision"] is False:
            findings.append(_finding("key-revision-disabled", "medium",
                "governance disables key revision", rule=index))
        for field in ("discovery_protection_kind", "liveliness_protection_kind",
                      "rtps_protection_kind", "rtps_psk_protection_kind"):
            if row[field] == "NONE":
                findings.append(_finding("unprotected-governance-scope", "high",
                    f"{field} is NONE", rule=index, field=field))
        topic_access = _one(rule, "topic_access_rules", required=True)
        assert topic_access is not None
        topic_rules = _children(topic_access, "topic_rule")
        if not topic_rules or len(topic_rules) > MAX_RULES:
            raise SecDDSSecurityError("governance topic-rule count is invalid")
        for topic_index, topic in enumerate(topic_rules):
            expression = _text(_one(topic, "topic_expression"), "topic_expression", required=True)
            assert expression is not None
            topic_row = {
                "index": topic_index,
                "topic_expression": expression,
                "enable_discovery_protection": _boolean(_one(topic, "enable_discovery_protection"),
                    "enable_discovery_protection", required=True),
                "enable_liveliness_protection": _boolean(_one(topic, "enable_liveliness_protection"),
                    "enable_liveliness_protection", required=True),
                "enable_read_access_control": _boolean(_one(topic, "enable_read_access_control"),
                    "enable_read_access_control", required=True),
                "enable_write_access_control": _boolean(_one(topic, "enable_write_access_control"),
                    "enable_write_access_control", required=True),
                "metadata_protection_kind": _protection(_one(topic, "metadata_protection_kind"),
                    "metadata_protection_kind", required=True),
                "data_protection_kind": _protection(_one(topic, "data_protection_kind"),
                    "data_protection_kind", basic=True, required=True),
            }
            if expression == "*":
                findings.append(_finding("wildcard-topic-governance", "medium",
                    "governance topic rule applies to every topic", rule=index, topic_rule=topic_index))
                if topic_index < len(topic_rules) - 1:
                    findings.append(_finding("topic-rule-shadowing", "high",
                        "first-match wildcard topic rule shadows later rules",
                        rule=index, topic_rule=topic_index))
            for access_field in ("enable_read_access_control", "enable_write_access_control"):
                if topic_row[access_field] is False:
                    findings.append(_finding("topic-access-control-disabled", "high",
                        f"{access_field} is false", rule=index, topic_rule=topic_index,
                        field=access_field))
            for protection_field in ("metadata_protection_kind", "data_protection_kind"):
                if topic_row[protection_field] == "NONE":
                    findings.append(_finding("unprotected-topic-scope", "high",
                        f"{protection_field} is NONE", rule=index, topic_rule=topic_index,
                        field=protection_field))
            row["topic_rules"].append(topic_row)
        algorithms = _one(rule, "allowed_crypto_algorithms")
        if algorithms is not None:
            row["allowed_crypto_algorithms"] = {
                _local(child.tag): [value.strip() for value in child.itertext() if value.strip()]
                for child in _children(algorithms)
            }
        out_rules.append(row)
    return {"domain_rules": out_rules}, findings


def _date(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (ValueError, OverflowError) as exc:
        raise SecDDSSecurityError(f"invalid {label} dateTime") from exc
    if parsed.tzinfo is None:
        raise SecDDSSecurityError(f"{label} must include a timezone")
    return parsed


def _criterion(element: ET.Element) -> dict[str, Any]:
    topics_el = _one(element, "topics", required=True)
    assert topics_el is not None
    topics = [_text(item, "topic", required=True) for item in _children(topics_el, "topic")]
    if not topics:
        raise SecDDSSecurityError("permission criterion has no topics")
    partitions_el = _one(element, "partitions")
    partitions = ([_text(item, "partition", required=True)
                   for item in _children(partitions_el, "partition")] if partitions_el is not None else [])
    tags_el = _one(element, "data_tags")
    tags = []
    if tags_el is not None:
        for tag in _children(tags_el, "tag"):
            name = _text(_one(tag, "name"), "data tag name", required=True)
            value = _text(_one(tag, "value"), "data tag value", required=True)
            tags.append({"name": name, "value": value})
    return {
        "topics": topics,
        "partitions": partitions,
        "partition_semantics": "default-empty-only" if not partitions else "explicit-patterns",
        "data_tags": tags,
    }


def _permission_rule(element: ET.Element, effect: str, index: int) -> dict[str, Any]:
    domains_el = _one(element, "domains", required=True)
    assert domains_el is not None
    result = {"index": index, "effect": effect, "domains": _domains(domains_el),
              "publish": [], "subscribe": [], "relay": []}
    for kind in ("publish", "subscribe", "relay"):
        for criterion in _children(element, kind):
            result[kind].append(_criterion(criterion))
            if len(result[kind]) > MAX_RULES:
                raise SecDDSSecurityError("permission criterion count exceeds limit")
    return result


def _rule_is_broad(rule: dict[str, Any]) -> bool:
    criteria = rule["publish"] + rule["subscribe"] + rule["relay"]
    return bool(criteria) and all(item["topics"] == ["*"] for item in criteria) and all(
        row["min"] == 0 and row["max"] == 0xFFFFFFFF for row in rule["domains"])


def _permissions(root: ET.Element, as_of: datetime | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    permissions = _one(root, "permissions", required=True)
    assert permissions is not None
    grants = _children(permissions, "grant")
    if not grants or len(grants) > MAX_RULES:
        raise SecDDSSecurityError("permission grant count is invalid")
    output: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    subjects: set[str] = set()
    for grant_index, grant in enumerate(grants):
        name = grant.get("name", "").strip()
        if not name or len(name) > MAX_NAME:
            raise SecDDSSecurityError("permission grant name is missing or over-limit")
        subject = _text(_one(grant, "subject_name"), "subject_name", required=True)
        assert subject is not None
        if subject in subjects:
            findings.append(_finding("duplicate-subject-grant", "high",
                "multiple grants bind the same subject", grant=grant_index, subject=subject))
        subjects.add(subject)
        validity = _one(grant, "validity", required=True)
        assert validity is not None
        before_text = _text(_one(validity, "not_before"), "not_before", required=True)
        after_text = _text(_one(validity, "not_after"), "not_after", required=True)
        assert before_text is not None and after_text is not None
        before, after = _date(before_text, "not_before"), _date(after_text, "not_after")
        if after <= before:
            findings.append(_finding("invalid-validity-window", "high",
                "permission grant not_after does not follow not_before", grant=grant_index))
        if as_of is not None:
            if as_of < before:
                findings.append(_finding("grant-not-yet-valid", "high",
                    "permission grant is not yet valid at the supplied time", grant=grant_index))
            elif as_of >= after:
                findings.append(_finding("grant-expired", "high",
                    "permission grant is expired at the supplied time", grant=grant_index))
        rules: list[dict[str, Any]] = []
        default_value: str | None = None
        for child in _children(grant):
            kind = _local(child.tag)
            if kind in {"allow_rule", "deny_rule"}:
                rules.append(_permission_rule(child, "ALLOW" if kind == "allow_rule" else "DENY", len(rules)))
            elif kind == "default":
                if default_value is not None:
                    raise SecDDSSecurityError("duplicate permission default")
                default_value = _text(child, "permission default", required=True)
        if len(rules) > MAX_RULES:
            raise SecDDSSecurityError("permission rule count exceeds limit")
        if default_value is None:
            effective_default = "DENY"
            findings.append(_finding("legacy-missing-default", "medium",
                "grant omits the 1.2-required default; legacy behavior is DENY", grant=grant_index))
        elif default_value not in {"ALLOW", "DENY"}:
            raise SecDDSSecurityError("permission default must be ALLOW or DENY")
        else:
            effective_default = default_value
        if effective_default == "ALLOW":
            findings.append(_finding("default-allow", "high",
                "permission grant defaults to ALLOW", grant=grant_index))
        for rule_index, rule in enumerate(rules):
            wildcard = any("*" in topic or "?" in topic
                for criterion in rule["publish"] + rule["subscribe"] + rule["relay"]
                for topic in criterion["topics"])
            if rule["effect"] == "ALLOW" and wildcard:
                findings.append(_finding("wildcard-allow", "high",
                    "ALLOW rule contains a wildcard topic expression",
                    grant=grant_index, rule=rule_index))
            if rule["effect"] == "ALLOW" and rule["relay"]:
                findings.append(_finding("relay-allow", "high",
                    "ALLOW rule permits relay behavior", grant=grant_index, rule=rule_index))
            if rule["effect"] == "ALLOW" and _rule_is_broad(rule) and rule_index < len(rules) - 1:
                findings.append(_finding("permission-rule-shadowing", "high",
                    "first-match broad ALLOW shadows later permission rules",
                    grant=grant_index, rule=rule_index))
        output.append({
            "index": grant_index,
            "name": name,
            "subject_name": subject,
            "subject_name_semantics": "exact-xsd-value",
            "validity": {"not_before": before.isoformat(), "not_after": after.isoformat()},
            "rules": rules,
            "default": default_value,
            "effective_default": effective_default,
        })
    return {"grants": output, "evaluated_at": as_of.isoformat() if as_of else None}, findings


def _parse_xml(raw: bytes, as_of: datetime | None) -> tuple[str, dict[str, Any], list[dict[str, Any]], str]:
    text = _xml_text(raw)
    builder = _BoundedTree()
    try:
        root = ET.fromstring(text, parser=ET.XMLParser(target=builder))
    except SecDDSSecurityError:
        raise
    except (ET.ParseError, ValueError, OverflowError, RecursionError) as exc:
        raise SecDDSSecurityError("malformed DDS security XML") from exc
    if _local(root.tag) != "dds":
        raise SecDDSSecurityError("DDS security XML root must be dds")
    has_governance = bool(_children(root, "domain_access_rules"))
    has_permissions = bool(_children(root, "permissions"))
    if has_governance == has_permissions:
        raise SecDDSSecurityError("XML must contain exactly one governance or permissions document")
    if has_governance:
        content, findings = _governance(root)
        kind = "governance"
    else:
        content, findings = _permissions(root, as_of)
        kind = "permissions"
    return kind, content, findings, text


def _mime_payload(raw: bytes) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise SecDDSSecurityError("malformed S/MIME message") from exc
    if message.defects:
        raise SecDDSSecurityError("S/MIME message has parser defects")
    if message.get_content_type().lower() != "multipart/signed" or not message.is_multipart():
        raise SecDDSSecurityError("S/MIME wrapper must be multipart/signed")
    parts = list(message.iter_parts())
    if len(parts) != 2 or any(part.defects for part in parts):
        raise SecDDSSecurityError("S/MIME multipart/signed must contain exactly two valid parts")
    protocol_name = (message.get_param("protocol", header="content-type") or "").lower()
    accepted = {"application/pkcs7-signature", "application/x-pkcs7-signature"}
    if protocol_name not in accepted:
        raise SecDDSSecurityError("S/MIME protocol is not PKCS#7 SignedData")
    signature_type = parts[1].get_content_type().lower()
    if signature_type not in accepted or signature_type != protocol_name:
        raise SecDDSSecurityError("S/MIME signature part does not match protocol parameter")
    try:
        xml = parts[0].get_payload(decode=True)
        signature = parts[1].get_payload(decode=True)
    except Exception as exc:
        raise SecDDSSecurityError("cannot decode S/MIME parts") from exc
    if not isinstance(xml, bytes) or not xml or len(xml) > MAX_XML:
        raise SecDDSSecurityError("S/MIME signed XML part is empty or over-limit")
    if not isinstance(signature, bytes) or not signature:
        raise SecDDSSecurityError("S/MIME signature part is empty")
    findings: list[dict[str, Any]] = []
    if protocol_name.startswith("application/x-"):
        findings.append(_finding("legacy-pkcs7-mime-alias", "low",
            "deployed x-pkcs7-signature alias is accepted for interoperability"))
    signed_data = _CMS_SIGNED_DATA_OID in signature
    if not signed_data:
        findings.append(_finding("cms-signeddata-not-recognized", "high",
            "signature bytes do not contain the PKCS#7 SignedData object identifier"))
    metadata = {
        "container": "smime-multipart-signed",
        "content_type": message.get_content_type(),
        "protocol": protocol_name,
        "micalg": message.get_param("micalg", header="content-type"),
        "xml_content_type": parts[0].get_content_type(),
        "signature_content_type": signature_type,
        "signature_present": True,
        "signature_length": len(signature),
        "cms_signed_data_oid_present": signed_data,
        "signer_certificate_included": "not-inspected",
        "signature_verification": "not-performed",
        "signature_verification_reason": "no Permissions CA trust material was supplied",
        "extracted_xml_sha256": hashlib.sha256(xml).hexdigest(),
    }
    return xml, metadata, findings


def _parse_as_of(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = _date(value, "as_of")
    else:
        raise SecDDSSecurityError("as_of must be an ISO dateTime string or datetime")
    if parsed.tzinfo is None:
        raise SecDDSSecurityError("as_of must include a timezone")
    return parsed


def parse_security_document(data: bytes | bytearray | memoryview, *,
                            as_of: str | datetime | None = None) -> dict[str, Any]:
    """Parse raw policy XML or a supplied S/MIME multipart/signed policy artifact."""
    try:
        raw = _blob(data, label="DDS security document")
        moment = _parse_as_of(as_of)
        stripped = raw.lstrip()
        mime_like = (stripped[:64].lower().startswith(b"mime-version:") or
                     stripped[:64].lower().startswith(b"content-type:"))
        if mime_like:
            xml, container, findings = _mime_payload(raw)
        else:
            xml = raw
            container = {
                "container": "raw-xml",
                "signature_present": False,
                "signature_verification": "not-performed",
                "signature_verification_reason": "raw XML has no detached signature wrapper",
                "extracted_xml_sha256": hashlib.sha256(xml).hexdigest(),
            }
            findings = [_finding("unsigned-policy-document", "high",
                "governance/permissions XML is not wrapped in multipart/signed S/MIME")]
        kind, content, policy_findings, text = _parse_xml(xml, moment)
        findings.extend(policy_findings)
        return {
            "format": "DDS-Security policy",
            "document_kind": kind,
            "container": container,
            "policy": content,
            "findings": findings,
            "xml_encoding_preview": text[:80],
            "network_requests": 0,
        }
    except SecDDSSecurityError:
        raise
    except Exception as exc:
        raise SecDDSSecurityError("malformed DDS security document") from exc


def analyze(data: bytes | bytearray | memoryview, *, mode: str = "auto", framing: str = "auto",
            as_of: str | datetime | None = None) -> dict[str, Any]:
    """Analyze supplied bytes as secure RTPS or a governance/permissions document."""
    try:
        if mode not in {"auto", "wire", "document"}:
            raise SecDDSSecurityError("mode must be auto, wire, or document")
        raw = _blob(data, label="DDS security evidence")
        if mode == "auto":
            stripped = raw.lstrip()
            prefix = stripped[:128].lower()
            mode = "document" if stripped.startswith((b"<", b"\xff\xfe", b"\xfe\xff")) or b"content-type:" in prefix else "wire"
        return (parse_secure_rtps(raw, framing=framing) if mode == "wire" else
                parse_security_document(raw, as_of=as_of))
    except SecDDSSecurityError:
        raise
    except Exception as exc:
        raise SecDDSSecurityError("cannot analyze DDS security evidence") from exc


def analyze_file(path: str | Path, *, mode: str = "auto", framing: str = "auto",
                 as_of: str | datetime | None = None) -> dict[str, Any]:
    """Read and analyze one bounded local artifact."""
    try:
        if not isinstance(path, (str, Path)):
            raise SecDDSSecurityError("path must be text or pathlib.Path")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise SecDDSSecurityError("DDS security artifact exceeds size limit")
        return analyze(raw, mode=mode, framing=framing, as_of=as_of)
    except SecDDSSecurityError:
        raise
    except Exception as exc:
        raise SecDDSSecurityError("cannot read DDS security artifact") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="secure RTPS bytes, governance XML, permissions XML, or S/MIME")
    parser.add_argument("--mode", choices=("auto", "wire", "document"), default="auto")
    parser.add_argument("--framing", choices=("auto", "rtps", "submessages"), default="auto")
    parser.add_argument("--as-of", help="ISO dateTime used only for permission validity evaluation")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = analyze_file(args.file, mode=args.mode, framing=args.framing, as_of=args.as_of)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except SecDDSSecurityError as exc:
        print(f"sec_dds_security: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "SecDDSSecurityError",
    "analyze",
    "analyze_file",
    "main",
    "parse_secure_rtps",
    "parse_security_document",
]


if __name__ == "__main__":
    raise SystemExit(main())
