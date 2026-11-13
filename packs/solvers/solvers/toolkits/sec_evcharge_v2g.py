#!/usr/bin/env python3
"""Passive ISO 15118/V2GTP/SDP and OCPP application-message analysis.

Inputs are already-supplied application bytes, decoded-message metadata, or JSON
transcripts.  This module never opens a socket, parses a live endpoint, constructs
traffic, or claims that a certificate/TLS control was verified from metadata alone.
Raw PCAP/TCP/TLS/WebSocket recovery belongs to the repository's existing network
forensics engines.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime
import functools
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


MAX_FRAME = 16 * 1024 * 1024
MAX_JSON = 8 * 1024 * 1024
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 32
MAX_TRANSCRIPT = 100_000
MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
MAX_CERT_RECORDS = 256
MAX_TEXT = 65_536


class SecEvchargeV2GError(ValueError):
    """Malformed, unsafe, unsupported, ambiguous, or over-limit supplied input."""


def _closed(function):
    """Keep the public API on one declared-exception contract."""
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecEvchargeV2GError:
            raise
        except Exception as exc:
            raise SecEvchargeV2GError(
                f"{function.__name__} failed: {type(exc).__name__}: {str(exc)[:240]}"
            ) from None
    return wrapper


def _blob(value: Any, *, maximum: int = MAX_FRAME, nonempty: bool = True) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecEvchargeV2GError("input must be bytes-like")
    result = bytes(value)
    if (nonempty and not result) or len(result) > maximum:
        raise SecEvchargeV2GError(f"input must contain {1 if nonempty else 0}..{maximum} bytes")
    return result


def _protocol(value: Any, *, optional: bool = False) -> str | None:
    aliases = {
        "iso2": "iso2", "15118-2": "iso2", "iso15118-2": "iso2",
        "iso20": "iso20", "15118-20": "iso20", "iso15118-20": "iso20",
    }
    if value is None and optional:
        return None
    if type(value) is not str or value.lower() not in aliases:
        raise SecEvchargeV2GError("protocol must be 'iso2' or 'iso20'")
    return aliases[value.lower()]


V2GTP_PAYLOAD_TYPES: dict[int, dict[str, str]] = {
    0x8001: {"name": "exi_or_supported_app_protocol", "family": "context_dependent"},
    0x8002: {"name": "iso15118_20_common_exi", "family": "iso20_common"},
    0x8003: {"name": "iso15118_20_ac_exi", "family": "iso20_ac"},
    0x8004: {"name": "iso15118_20_dc_exi", "family": "iso20_dc"},
    0x8005: {"name": "iso15118_20_acdp_exi", "family": "iso20_acdp"},
    0x8006: {"name": "iso15118_20_wpt_exi", "family": "iso20_wpt"},
    0x8101: {"name": "schedule_renegotiation", "family": "iso20_auxiliary"},
    0x8102: {"name": "metering_confirmation", "family": "iso20_auxiliary"},
    0x8103: {"name": "acdp_system_status", "family": "iso20_auxiliary"},
    0x8104: {"name": "parking_status", "family": "iso20_auxiliary"},
    0x9000: {"name": "wired_sdp_request", "family": "sdp"},
    0x9001: {"name": "wired_sdp_response", "family": "sdp"},
    0x9002: {"name": "wireless_sdp_request", "family": "wireless_sdp"},
    0x9003: {"name": "wireless_sdp_response", "family": "wireless_sdp"},
}

_SDP_SECURITY = {0x00: "tls", 0x10: "no_transport_security"}
_SDP_TRANSPORT = {0x00: "tcp", 0x10: "udp"}
_SDP_MIN_DYNAMIC_PORT = 49_152


def _decode_wired_sdp(payload_type: int, payload: bytes) -> dict[str, Any]:
    if payload_type in (0x9002, 0x9003):
        raise SecEvchargeV2GError("wireless SDP has a distinct layout and is not decoded as wired SDP")
    if payload_type == 0x9000:
        if len(payload) != 2:
            raise SecEvchargeV2GError("wired SDP request payload must be exactly 2 bytes")
        security, transport = payload
        if security not in _SDP_SECURITY or transport not in _SDP_TRANSPORT:
            raise SecEvchargeV2GError("wired SDP request contains a reserved enum value")
        return {
            "kind": "request", "security": _SDP_SECURITY[security],
            "security_code": security, "transport": _SDP_TRANSPORT[transport],
            "transport_code": transport,
            "limitations": ["The security selector is preference metadata, not evidence that TLS occurred."],
        }
    if payload_type == 0x9001:
        if len(payload) != 20:
            raise SecEvchargeV2GError("wired SDP response payload must be exactly 20 bytes")
        security, transport = payload[18], payload[19]
        if security not in _SDP_SECURITY or transport not in _SDP_TRANSPORT:
            raise SecEvchargeV2GError("wired SDP response contains a reserved enum value")
        port = int.from_bytes(payload[16:18], "big")
        if port < _SDP_MIN_DYNAMIC_PORT:
            raise SecEvchargeV2GError(
                "wired SDP response SECC port must be in the dynamic/private range 49152..65535"
            )
        address = str(ipaddress.IPv6Address(payload[:16]))
        return {
            "kind": "response", "ipv6": address,
            "port": port,
            "security": _SDP_SECURITY[security], "security_code": security,
            "transport": _SDP_TRANSPORT[transport], "transport_code": transport,
            "limitations": [
                "The advertised endpoint is reported only; this analyzer never contacts it.",
                "The security selector is not evidence that TLS occurred.",
            ],
        }
    raise SecEvchargeV2GError("payload type is not wired SDP")


@_closed
def parse_wired_sdp(payload: Any, *, response: bool = False) -> dict[str, Any]:
    """Decode an exact wired SDP request or response payload (not its V2GTP header)."""
    if type(response) is not bool:
        raise SecEvchargeV2GError("response must be boolean")
    return _decode_wired_sdp(0x9001 if response else 0x9000, _blob(payload, maximum=20))


def _inspect_exi(data: bytes) -> dict[str, Any]:
    offset = 0
    cookie = data.startswith(b"$EXI")
    if cookie:
        offset = 4
    if offset >= len(data):
        raise SecEvchargeV2GError("EXI cookie is not followed by an EXI header")
    first = data[offset]
    if first >> 6 != 0b10:
        raise SecEvchargeV2GError("EXI distinguishing bits are not '10'")
    options = bool(first & 0x20)
    preview = bool(first & 0x10)
    version_code = first & 0x0F
    # Values 15+ use continuation nibbles whose following bit position depends on
    # EXI bit packing.  Decline instead of guessing the body boundary.
    if version_code == 0x0F:
        raise SecEvchargeV2GError("extended EXI version fields are unsupported")
    body_byte_offset = offset + 1 if not options else None
    return {
        "cookie": cookie,
        "distinguishing_bits": "10",
        "options_present": options,
        "preview": preview,
        "version_code": version_code,
        "exi_version": f"1.{version_code}" if not preview else f"preview-1.{version_code}",
        "header_byte_offset": offset,
        "body_byte_offset": body_byte_offset,
        "body_bytes_if_byte_aligned": len(data) - body_byte_offset if body_byte_offset is not None else None,
        "opaque_hex": data[offset + 1:].hex(),
        "semantic_decode": False,
        "limitations": [
            "Only the EXI header is inspected; the body remains opaque without the exact negotiated schema grammar.",
            "EXI options make the body bit boundary grammar-dependent." if options else
            "The reported body boundary applies to the minimal no-options header only.",
        ],
    }


@_closed
def inspect_exi_header(data: Any) -> dict[str, Any]:
    """Inspect a bounded EXI header without pretending to decode schema-informed content."""
    return _inspect_exi(_blob(data))


@_closed
def parse_v2gtp(data: Any, *, protocol: str | None = None) -> dict[str, Any]:
    """Parse exactly one V2GTP frame; concatenation and trailing bytes are rejected."""
    frame = _blob(data)
    selected = _protocol(protocol, optional=True)
    if len(frame) < 8:
        raise SecEvchargeV2GError("V2GTP frame is shorter than its 8-byte header")
    version, inverse = frame[0], frame[1]
    if version != 0x01 or inverse != 0xFE or (version ^ inverse) != 0xFF:
        raise SecEvchargeV2GError("V2GTP requires the 0x01/0xFE version pair")
    payload_type = int.from_bytes(frame[2:4], "big")
    length = int.from_bytes(frame[4:8], "big")
    if length > MAX_FRAME - 8:
        raise SecEvchargeV2GError("V2GTP payload length exceeds the configured cap")
    if len(frame) != 8 + length:
        raise SecEvchargeV2GError("V2GTP declared payload length does not exactly consume the frame")
    payload = frame[8:]
    known = V2GTP_PAYLOAD_TYPES.get(payload_type)
    manufacturer = 0xA000 <= payload_type <= 0xFFFF
    if known is None and not manufacturer:
        raise SecEvchargeV2GError(f"reserved or unsupported V2GTP payload type 0x{payload_type:04x}")
    result: dict[str, Any] = {
        "format": "v2gtp", "version": version, "inverse_version": inverse,
        "payload_type": f"0x{payload_type:04x}", "payload_length": length,
        "payload_hex": payload.hex(), "protocol_context": selected,
    }
    if manufacturer:
        result.update(name="manufacturer_specific", family="opaque", semantic_decode=False)
        result["limitations"] = ["Manufacturer-specific payload is preserved as opaque bytes."]
        return result
    result.update(known)
    if selected == "iso2" and 0x8002 <= payload_type <= 0x8104:
        raise SecEvchargeV2GError("ISO 15118-20 payload type supplied with ISO 15118-2 context")
    if payload_type in (0x9000, 0x9001):
        result["sdp"] = _decode_wired_sdp(payload_type, payload)
    elif payload_type in (0x9002, 0x9003):
        result["semantic_decode"] = False
        result["limitations"] = ["Wireless SDP is intentionally not interpreted with the wired SDP layout."]
    elif 0x8001 <= payload_type <= 0x8006:
        if payload_type == 0x8001:
            if selected is None:
                result["ambiguity"] = "0x8001 requires caller-supplied iso2/iso20 context"
            else:
                result["family"] = "iso2_exi_or_sap" if selected == "iso2" else "iso20_supported_app_protocol"
        result["exi_header"] = _inspect_exi(payload)
    else:
        result["semantic_decode"] = False
        result["limitations"] = ["Auxiliary payload semantics require their exact ISO 15118-20 grammar."]
    return result


ISO2_MESSAGES = (
    "SessionSetup", "ServiceDiscovery", "ServiceDetail", "PaymentServiceSelection",
    "PaymentDetails", "Authorization", "ChargeParameterDiscovery", "PowerDelivery",
    "ChargingStatus", "MeteringReceipt", "CableCheck", "PreCharge", "CurrentDemand",
    "WeldingDetection", "CertificateInstallation", "CertificateUpdate", "SessionStop",
)

ISO20_MESSAGE_FAMILIES: dict[str, tuple[str, ...]] = {
    "common": (
        "SessionSetup", "AuthorizationSetup", "Authorization", "ServiceDiscovery",
        "ServiceDetail", "ServiceSelection", "ScheduleExchange", "PowerDelivery",
        "MeteringConfirmation", "CertificateInstallation", "SessionStop",
        "VehicleCheckIn", "VehicleCheckOut",
    ),
    "ac": ("AC_ChargeParameterDiscovery", "AC_ChargeLoop"),
    "dc": (
        "DC_ChargeParameterDiscovery", "DC_CableCheck", "DC_PreCharge",
        "DC_ChargeLoop", "DC_WeldingDetection",
    ),
    "wpt": (
        "WPT_ChargeParameterDiscovery", "WPT_FinePositioningSetup",
        "WPT_FinePositioning", "WPT_Pairing", "WPT_AlignmentCheck",
        "WPT_ChargeLoop",
    ),
    "acdp": (
        "ACDP_VehiclePositioning", "ACDP_Connect", "ACDP_Disconnect",
        "ACDP_SystemStatus",
    ),
}

ISO20_SERVICES = {
    1: "AC", 2: "DC", 3: "WPT", 4: "DC_ACDP", 5: "AC_BPT", 6: "DC_BPT",
    7: "DC_ACDP_BPT", 65: "Internet", 66: "ParkingStatus",
}

_PHASES = {
    "SessionSetup": 0, "ServiceDiscovery": 1, "ServiceDetail": 1,
    "AuthorizationSetup": 2, "PaymentServiceSelection": 2, "PaymentDetails": 2,
    "CertificateInstallation": 2, "CertificateUpdate": 2, "Authorization": 3,
    "ServiceSelection": 3, "ChargeParameterDiscovery": 4,
    "AC_ChargeParameterDiscovery": 4, "DC_ChargeParameterDiscovery": 4,
    "WPT_ChargeParameterDiscovery": 4, "ScheduleExchange": 4,
    "CableCheck": 5, "DC_CableCheck": 5, "PreCharge": 5,
    "DC_PreCharge": 5, "PowerDelivery": 6, "ChargingStatus": 7,
    "CurrentDemand": 7, "AC_ChargeLoop": 7, "DC_ChargeLoop": 7,
    "WPT_ChargeLoop": 7, "MeteringReceipt": 7, "MeteringConfirmation": 7,
    "WeldingDetection": 8, "DC_WeldingDetection": 8,
    "SessionStop": 9,
}


@_closed
def iso15118_catalog(generation: Any, *, amendment_1: bool = False) -> dict[str, Any]:
    """Return a version-gated message/service catalog, not an EXI decoder."""
    selected = _protocol(generation)
    if type(amendment_1) is not bool:
        raise SecEvchargeV2GError("amendment_1 must be boolean")
    if selected == "iso2":
        if amendment_1:
            raise SecEvchargeV2GError("ISO 15118-20 Amendment 1 does not apply to ISO 15118-2")
        return {
            "generation": "ISO 15118-2:2014", "message_bases": list(ISO2_MESSAGES),
            "request_response_suffixes": ["Req", "Res"],
            "control_modes": ["scheduled"],
            "limitations": ["This is a message catalog; decoding still requires the negotiated EXI schema."],
        }
    result = {
        "generation": "ISO 15118-20:2022" + (" + Amendment 1:2026" if amendment_1 else ""),
        "message_families": {key: list(value) for key, value in ISO20_MESSAGE_FAMILIES.items()},
        "services": {str(key): value for key, value in ISO20_SERVICES.items()},
        "control_modes": ["scheduled", "dynamic"],
        "bidirectional_services": [5, 6, 7],
        "amendment_1_features": ["AC_DER", "MCS", "improved_security_concept"] if amendment_1 else [],
        "limitations": ["Amendment 1 features are reported only when explicitly selected."],
    }
    return result


def _message_bases(generation: str) -> set[str]:
    if generation == "iso2":
        return set(ISO2_MESSAGES)
    return {name for values in ISO20_MESSAGE_FAMILIES.values() for name in values}


@_closed
def analyze_iso15118_transcript(records: Any, *, generation: Any) -> dict[str, Any]:
    """Check a caller-decoded ISO 15118 message transcript without decoding EXI."""
    selected = _protocol(generation)
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise SecEvchargeV2GError("records must be a sequence of decoded-message mappings")
    if not 1 <= len(records) <= MAX_TRANSCRIPT:
        raise SecEvchargeV2GError("transcript record count is outside the configured bound")
    allowed = _message_bases(selected)
    normalized: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    pending: tuple[str, int] | None = None
    last_phase = -1
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise SecEvchargeV2GError(f"record {index} must be a mapping")
        message, direction = raw.get("message"), raw.get("direction")
        if type(message) is not str or not 4 <= len(message) <= 96:
            raise SecEvchargeV2GError(f"record {index} has an invalid message name")
        if direction not in ("evcc_to_secc", "secc_to_evcc"):
            raise SecEvchargeV2GError(f"record {index} direction must be evcc_to_secc or secc_to_evcc")
        if message.endswith("Req"):
            base, kind = message[:-3], "request"
            expected_direction = "evcc_to_secc"
        elif message.endswith("Res"):
            base, kind = message[:-3], "response"
            expected_direction = "secc_to_evcc"
        else:
            raise SecEvchargeV2GError(f"record {index} must use a Req/Res message name")
        if base not in allowed:
            issues.append({"code": "generation_message_mismatch", "index": index, "message": message})
        if direction != expected_direction:
            issues.append({"code": "direction_mismatch", "index": index, "expected": expected_direction})
        if kind == "request":
            if pending is not None:
                issues.append({"code": "request_before_response", "index": index,
                               "pending_message": pending[0], "pending_index": pending[1]})
            pending = (base, index)
        elif pending is None:
            issues.append({"code": "orphan_response", "index": index, "message": message})
        elif pending[0] != base:
            issues.append({"code": "response_pair_mismatch", "index": index,
                           "expected": pending[0] + "Res", "actual": message})
            pending = None
        else:
            pending = None
        phase = _PHASES.get(base)
        if phase is not None and kind == "request":
            # Repeated loop messages are normal; a substantial backwards jump is not.
            if phase + 1 < last_phase and base not in {"PowerDelivery", "Authorization", "ScheduleExchange"}:
                issues.append({"code": "ceremony_phase_regression", "index": index,
                               "phase": phase, "previous_phase": last_phase})
            last_phase = max(last_phase, phase)
        family = raw.get("family")
        if family is not None and (type(family) is not str or len(family) > 64):
            raise SecEvchargeV2GError(f"record {index} family must be bounded text or omitted")
        normalized.append({"index": index, "message": message, "base": base,
                           "kind": kind, "direction": direction, "family": family})
    if pending is not None:
        issues.append({"code": "unanswered_request", "index": pending[1], "message": pending[0] + "Req"})
    if normalized[0]["message"] != "SessionSetupReq":
        issues.append({"code": "capture_does_not_start_at_session_setup", "severity": "note"})
    if normalized[-1]["message"] != "SessionStopRes":
        issues.append({"code": "capture_does_not_end_at_session_stop", "severity": "note"})
    hard = [row for row in issues if row.get("severity") != "note"]
    return {
        "generation": selected, "messages": normalized, "issues": issues,
        "pairing_valid": not hard, "semantic_decode": "caller_supplied",
        "limitations": ["Message labels are caller-supplied; this function does not decode or authenticate EXI."],
    }


PNC_ROLES = {
    "v2g_root": {"ca": True, "identifier": None},
    "cpo_sub_ca": {"ca": True, "identifier": None},
    "secc_leaf": {"ca": False, "identifier": "EVSEID"},
    "oem_root": {"ca": True, "identifier": None},
    "oem_sub_ca": {"ca": True, "identifier": None},
    "oem_provisioning_leaf": {"ca": False, "identifier": "PCID"},
    "cps_sub_ca": {"ca": True, "identifier": None},
    "mo_root": {"ca": True, "identifier": None},
    "mo_sub_ca": {"ca": True, "identifier": None},
    "contract_leaf": {"ca": False, "identifier": "eMAID"},
}

PNC_CEREMONIES = {
    "iso2": (
        "TLS_SECC_AUTH", "CertificateInstallationReq", "CertificateInstallationRes",
        "PaymentDetailsReq", "PaymentDetailsRes", "AuthorizationReq", "AuthorizationRes",
    ),
    "iso20": (
        "TLS_SECC_AUTH", "AuthorizationSetupReq", "AuthorizationSetupRes",
        "CertificateInstallationReq", "CertificateInstallationRes",
        "AuthorizationReq", "AuthorizationRes",
    ),
}
# Backward-compatible catalog name for callers that explicitly want the -2 path.
PNC_CEREMONY = PNC_CEREMONIES["iso2"]


@_closed
def analyze_pnc_evidence(evidence: Any, *, generation: Any = None) -> dict[str, Any]:
    """Analyze caller-supplied PnC certificate-role/ceremony metadata, never live PKI."""
    if not isinstance(evidence, Mapping):
        raise SecEvchargeV2GError("PnC evidence must be a mapping")
    selected = _protocol(generation if generation is not None else evidence.get("generation"))
    certs = evidence.get("certificates", [])
    ceremony = evidence.get("ceremony", [])
    if not isinstance(certs, Sequence) or isinstance(certs, (str, bytes)) or len(certs) > MAX_CERT_RECORDS:
        raise SecEvchargeV2GError("certificates must be a bounded sequence")
    if not isinstance(ceremony, Sequence) or isinstance(ceremony, (str, bytes)) or len(ceremony) > 128:
        raise SecEvchargeV2GError("ceremony must be a bounded sequence")
    issues: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(certs):
        if not isinstance(item, Mapping):
            raise SecEvchargeV2GError(f"certificate record {index} must be a mapping")
        role = item.get("role")
        if role not in PNC_ROLES:
            raise SecEvchargeV2GError(f"certificate record {index} has an unknown PnC role")
        is_ca = item.get("is_ca")
        if is_ca is not None and type(is_ca) is not bool:
            raise SecEvchargeV2GError(f"certificate record {index} is_ca must be boolean or omitted")
        expected_ca = PNC_ROLES[role]["ca"]
        if is_ca is not None and is_ca != expected_ca:
            issues.append({"code": "basic_constraints_role_mismatch", "index": index,
                           "role": role, "expected_ca": expected_ca})
        identifier = item.get("identifier_type")
        expected_identifier = PNC_ROLES[role]["identifier"]
        if identifier is not None and (type(identifier) is not str or len(identifier) > 32):
            raise SecEvchargeV2GError(
                f"certificate record {index} identifier_type must be bounded text or omitted"
            )
        if identifier is not None and identifier != expected_identifier:
            issues.append({"code": "identifier_role_mismatch", "index": index, "role": role,
                           "expected": expected_identifier, "actual": identifier})
        issuer_role = item.get("issuer_role")
        if issuer_role is not None and issuer_role not in PNC_ROLES:
            raise SecEvchargeV2GError(f"certificate record {index} has an unknown issuer_role")
        rows.append({"index": index, "role": role, "is_ca": is_ca,
                     "identifier_type": identifier, "issuer_role": issuer_role})
    expected_edges = {
        "v2g_root": set(), "oem_root": set(), "mo_root": set(),
        "cpo_sub_ca": {"v2g_root"}, "secc_leaf": {"cpo_sub_ca"},
        "oem_sub_ca": {"oem_root"}, "oem_provisioning_leaf": {"oem_sub_ca"},
        "cps_sub_ca": {"v2g_root"}, "mo_sub_ca": {"mo_root"},
        "contract_leaf": {"mo_sub_ca"},
    }
    for row in rows:
        allowed_issuers = expected_edges.get(row["role"])
        if (row["issuer_role"] is not None and allowed_issuers is not None
                and row["issuer_role"] not in allowed_issuers):
            issues.append({"code": "unexpected_role_edge", "index": row["index"],
                           "role": row["role"], "issuer_role": row["issuer_role"],
                           "expected": sorted(allowed_issuers)})
    normalized_ceremony: list[str] = []
    previous = -1
    allowed_ceremony = PNC_CEREMONIES[selected]
    for index, value in enumerate(ceremony):
        if type(value) is not str or value not in allowed_ceremony:
            raise SecEvchargeV2GError(
                f"ceremony record {index} is not a known {selected} PnC step"
            )
        position = allowed_ceremony.index(value)
        if position < previous:
            issues.append({"code": "ceremony_order_regression", "index": index, "step": value})
        previous = max(previous, position)
        normalized_ceremony.append(value)
    roots = evidence.get("trust_anchors")
    validation_time = evidence.get("validation_time")
    revocation = evidence.get("revocation_evidence")
    trust_inputs_complete = bool(roots) and validation_time is not None and revocation is not None
    return {
        "generation": selected, "certificate_roles": rows,
        "ceremony": normalized_ceremony, "issues": issues,
        "topology_consistent": not issues,
        "trust_verdict": "not_performed",
        "trust_inputs_present": trust_inputs_complete,
        "limitations": [
            "Certificate records are caller-supplied metadata; generic DER facts belong to asn1_reader.py.",
            "No path signatures, names, validity, CRL, or OCSP are fetched or cryptographically verified.",
            "Presence of trust inputs is not a trust verdict.",
        ],
    }


OCPP16_CORE_ACTIONS = frozenset({
    "Authorize", "BootNotification", "CancelReservation", "ChangeAvailability",
    "ChangeConfiguration", "ClearCache", "ClearChargingProfile", "DataTransfer",
    "DiagnosticsStatusNotification", "FirmwareStatusNotification", "GetCompositeSchedule",
    "GetConfiguration", "GetDiagnostics", "GetLocalListVersion", "Heartbeat", "MeterValues",
    "RemoteStartTransaction", "RemoteStopTransaction", "ReserveNow", "Reset", "SendLocalList",
    "SetChargingProfile", "StartTransaction", "StatusNotification", "StopTransaction",
    "TriggerMessage", "UnlockConnector", "UpdateFirmware",
})
OCPP16_SECURITY_ACTIONS = frozenset({
    "CertificateSigned", "DeleteCertificate", "ExtendedTriggerMessage",
    "GetInstalledCertificateIds", "GetLog", "InstallCertificate", "LogStatusNotification",
    "SecurityEventNotification", "SignCertificate", "SignedFirmwareStatusNotification",
    "SignedUpdateFirmware",
})
OCPP201_ACTIONS = frozenset({
    "Authorize", "BootNotification", "CancelReservation", "CertificateSigned",
    "ChangeAvailability", "ClearCache", "ClearChargingProfile", "ClearDisplayMessage",
    "ClearVariableMonitoring", "ClearedChargingLimit", "CostUpdated", "CustomerInformation",
    "DataTransfer", "DeleteCertificate", "FirmwareStatusNotification", "Get15118EVCertificate",
    "GetBaseReport", "GetCertificateStatus", "GetChargingProfiles", "GetCompositeSchedule",
    "GetDisplayMessages", "GetInstalledCertificateIds", "GetLocalListVersion", "GetLog",
    "GetMonitoringReport", "GetReport", "GetTransactionStatus", "GetVariables", "Heartbeat",
    "InstallCertificate", "LogStatusNotification", "MeterValues", "NotifyChargingLimit",
    "NotifyCustomerInformation", "NotifyDisplayMessages", "NotifyEVChargingNeeds",
    "NotifyEVChargingSchedule", "NotifyEvent", "NotifyMonitoringReport", "NotifyReport",
    "PublishFirmware", "PublishFirmwareStatusNotification", "ReportChargingProfiles",
    "RequestStartTransaction", "RequestStopTransaction", "ReservationStatusUpdate", "ReserveNow",
    "Reset", "SecurityEventNotification", "SendLocalList", "SetChargingProfile",
    "SetDisplayMessage", "SetMonitoringBase", "SetMonitoringLevel", "SetNetworkProfile",
    "SetVariableMonitoring", "SetVariables", "SignCertificate", "StatusNotification",
    "TransactionEvent", "TriggerMessage", "UnlockConnector", "UnpublishFirmware", "UpdateFirmware",
})
OCPP16_ERRORS = frozenset({
    "NotImplemented", "NotSupported", "InternalError", "ProtocolError", "SecurityError",
    "FormationViolation", "PropertyConstraintViolation", "OccurenceConstraintViolation",
    "TypeConstraintViolation", "GenericError",
})
OCPP201_ERRORS = frozenset({
    "FormatViolation", "GenericError", "InternalError", "MessageTypeNotSupported",
    "NotImplemented", "NotSupported", "OccurrenceConstraintViolation",
    "PropertyConstraintViolation", "ProtocolError", "RpcFrameworkError", "SecurityError",
    "TypeConstraintViolation",
})


def _ocpp_version(value: Any) -> str:
    aliases = {"1.6": "1.6J", "1.6j": "1.6J", "ocpp1.6": "1.6J",
               "2.0.1": "2.0.1", "ocpp2.0.1": "2.0.1"}
    if type(value) is not str or value.lower() not in aliases:
        raise SecEvchargeV2GError("OCPP version must explicitly be 1.6J or 2.0.1")
    return aliases[value.lower()]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecEvchargeV2GError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise SecEvchargeV2GError(f"non-finite JSON constant {value!r} is forbidden")


def _json_bounds(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        raise SecEvchargeV2GError("JSON structure exceeds node/depth bounds")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_TEXT:
            raise SecEvchargeV2GError("JSON string exceeds the configured bound")
    elif isinstance(value, list):
        for item in value:
            _json_bounds(item, depth + 1, budget)
    elif isinstance(value, dict):
        for key, item in value.items():
            if type(key) is not str:
                raise SecEvchargeV2GError("JSON object key is not text")
            _json_bounds(key, depth + 1, budget)
            _json_bounds(item, depth + 1, budget)
    elif type(value) is int and value.bit_length() > 4096:
        raise SecEvchargeV2GError("JSON integer exceeds the configured bound")
    elif value is not None and type(value) not in (bool, int, float):
        raise SecEvchargeV2GError("unsupported JSON value type")
    if type(value) is float and not math.isfinite(value):
        raise SecEvchargeV2GError("non-finite JSON number is forbidden")


def _load_json(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = _blob(value, maximum=MAX_JSON)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecEvchargeV2GError("OCPP JSON is not valid UTF-8") from exc
    elif type(value) is str:
        if not value or len(value.encode("utf-8")) > MAX_JSON:
            raise SecEvchargeV2GError("JSON text is empty or exceeds the configured bound")
        text = value
    else:
        raise SecEvchargeV2GError("JSON input must be UTF-8 bytes or text")
    decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)
    start = len(text) - len(text.lstrip())
    try:
        result, end = decoder.raw_decode(text, start)
    except SecEvchargeV2GError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise SecEvchargeV2GError(f"invalid JSON: {exc}") from exc
    if text[end:].strip():
        raise SecEvchargeV2GError("trailing data follows the JSON value")
    _json_bounds(result)
    return result


def _nonempty_text(value: Any, name: str, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise SecEvchargeV2GError(f"{name} must be nonempty text of at most {maximum} characters")
    return value


def _require_keys(payload: dict[str, Any], required: set[str], action: str) -> None:
    missing = sorted(required - payload.keys())
    if missing:
        raise SecEvchargeV2GError(f"{action} payload lacks required fields: {', '.join(missing)}")


def _rfc3339(value: Any, name: str) -> None:
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
    ):
        raise SecEvchargeV2GError(f"{name} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise SecEvchargeV2GError(f"{name} is not a real RFC 3339 calendar timestamp") from exc
    if parsed.tzinfo is None:
        raise SecEvchargeV2GError(f"{name} must include an RFC 3339 offset")


def _validate_boot_call(payload: dict[str, Any], version: str) -> dict[str, Any]:
    if version == "1.6J":
        _require_keys(payload, {"chargePointVendor", "chargePointModel"}, "BootNotification")
        _nonempty_text(payload["chargePointVendor"], "chargePointVendor", 20)
        _nonempty_text(payload["chargePointModel"], "chargePointModel", 20)
        allowed = {"chargePointVendor", "chargePointModel", "chargePointSerialNumber", "chargeBoxSerialNumber",
                   "firmwareVersion", "iccid", "imsi", "meterType", "meterSerialNumber"}
        if set(payload) - allowed:
            raise SecEvchargeV2GError("OCPP 1.6 BootNotification contains unknown properties")
    else:
        _require_keys(payload, {"reason", "chargingStation"}, "BootNotification")
        if payload["reason"] not in {"ApplicationReset", "FirmwareUpdate", "LocalReset", "PowerUp",
                                     "RemoteReset", "ScheduledReset", "Triggered", "Unknown", "Watchdog"}:
            raise SecEvchargeV2GError("OCPP 2.0.1 BootNotification reason is invalid")
        station = payload["chargingStation"]
        if not isinstance(station, dict):
            raise SecEvchargeV2GError("chargingStation must be an object")
        _require_keys(station, {"model", "vendorName"}, "chargingStation")
        _nonempty_text(station["model"], "chargingStation.model", 20)
        _nonempty_text(station["vendorName"], "chargingStation.vendorName", 50)
    return {
        "profile": "published_boot_notification_required_shape",
        "required_fields_checked": True,
        "full_schema_validation": False,
    }


def _validate_boot_result(payload: dict[str, Any]) -> dict[str, Any]:
    _require_keys(payload, {"currentTime", "interval", "status"}, "BootNotificationResponse")
    _rfc3339(payload["currentTime"], "currentTime")
    if type(payload["interval"]) is not int or payload["interval"] < 0:
        raise SecEvchargeV2GError("BootNotificationResponse interval must be a nonnegative integer")
    if payload["status"] not in {"Accepted", "Pending", "Rejected"}:
        raise SecEvchargeV2GError("BootNotificationResponse status is invalid")
    return {
        "profile": "published_boot_notification_response_required_shape",
        "required_fields_checked": True,
        "full_schema_validation": False,
    }


def _validate_call_payload(action: str, payload: dict[str, Any], version: str) -> dict[str, Any] | None:
    if action == "BootNotification":
        return _validate_boot_call(payload, version)
    if version == "1.6J" and action == "DataTransfer":
        _require_keys(payload, {"vendorId"}, action)
        vendor = _nonempty_text(payload["vendorId"], "vendorId", 255)
        if "messageId" in payload:
            _nonempty_text(payload["messageId"], "messageId", 50)
        if "data" in payload and type(payload["data"]) is not str:
            raise SecEvchargeV2GError("DataTransfer.data must be text when present")
        bridge = vendor == "org.openchargealliance.iso15118pnc"
        return {"profile": "data_transfer", "iso15118_pnc_bridge": bridge,
                "bridge_message_id": payload.get("messageId") if bridge else None}
    if version == "2.0.1" and action == "Get15118EVCertificate":
        _require_keys(payload, {"iso15118SchemaVersion", "action", "exiRequest"}, action)
        _nonempty_text(payload["iso15118SchemaVersion"], "iso15118SchemaVersion", 50)
        if payload["action"] not in {"Install", "Update"}:
            raise SecEvchargeV2GError("Get15118EVCertificate.action must be Install or Update")
        encoded = _nonempty_text(payload["exiRequest"], "exiRequest", 5600)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SecEvchargeV2GError("Get15118EVCertificate.exiRequest is not canonical Base64") from exc
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise SecEvchargeV2GError(
                "Get15118EVCertificate.exiRequest is not canonical Base64"
            )
        return {"profile": "get_15118_ev_certificate", "exi_bytes": len(decoded),
                "semantic_decode": False}
    return None


def _parse_ocpp(value: Any, version: str, response_action: str | None) -> dict[str, Any]:
    message = _load_json(value)
    if not isinstance(message, list) or not message:
        raise SecEvchargeV2GError("OCPP application message must be a nonempty JSON array")
    message_type = message[0]
    if type(message_type) is not int:
        raise SecEvchargeV2GError("OCPP message type must be an integer, not a boolean or other value")
    if message_type in (5, 6):
        raise SecEvchargeV2GError("OCPP message type 5/6 is OCPP 2.1-only")
    expected = {2: 4, 3: 3, 4: 5}.get(message_type)
    if expected is None:
        raise SecEvchargeV2GError(f"unsupported OCPP message type {message_type}")
    if len(message) != expected:
        raise SecEvchargeV2GError(f"OCPP message type {message_type} requires exactly {expected} elements")
    if message_type != 3 and response_action is not None:
        raise SecEvchargeV2GError("response_action applies only to an OCPP CALLRESULT")
    unique_id = _nonempty_text(message[1], "uniqueId", 36)
    if message_type == 2:
        action = _nonempty_text(message[2], "action", 64)
        payload = message[3]
        if not isinstance(payload, dict):
            raise SecEvchargeV2GError("OCPP CALL payload must be an object")
        actions = OCPP16_CORE_ACTIONS | OCPP16_SECURITY_ACTIONS if version == "1.6J" else OCPP201_ACTIONS
        if action not in actions:
            raise SecEvchargeV2GError(f"action {action!r} is not defined for OCPP {version}")
        profile = _validate_call_payload(action, payload, version)
        return {"version": version, "message_type": 2, "kind": "CALL", "unique_id": unique_id,
                "action": action, "action_profile": "security_extension" if version == "1.6J" and
                action in OCPP16_SECURITY_ACTIONS else "core", "payload": payload,
                "payload_check": profile}
    if message_type == 3:
        payload = message[2]
        if not isinstance(payload, dict):
            raise SecEvchargeV2GError("OCPP CALLRESULT payload must be an object")
        check = None
        if response_action is not None:
            if type(response_action) is not str:
                raise SecEvchargeV2GError("response_action must be text or omitted")
            actions = OCPP16_CORE_ACTIONS | OCPP16_SECURITY_ACTIONS if version == "1.6J" else OCPP201_ACTIONS
            if response_action not in actions:
                raise SecEvchargeV2GError(f"response_action {response_action!r} is not defined for OCPP {version}")
            if response_action == "BootNotification":
                check = _validate_boot_result(payload)
        return {"version": version, "message_type": 3, "kind": "CALLRESULT",
                "unique_id": unique_id, "response_action": response_action,
                "payload": payload, "payload_check": check}
    error_code = _nonempty_text(message[2], "errorCode", 64)
    errors = OCPP16_ERRORS if version == "1.6J" else OCPP201_ERRORS
    if error_code not in errors:
        raise SecEvchargeV2GError(f"error code {error_code!r} is not defined for OCPP {version}")
    description = message[3]
    details = message[4]
    if type(description) is not str or len(description) > MAX_TEXT or not isinstance(details, dict):
        raise SecEvchargeV2GError("OCPP CALLERROR requires text description and object details")
    return {"version": version, "message_type": 4, "kind": "CALLERROR", "unique_id": unique_id,
            "error_code": error_code, "description": description, "details": details}


@_closed
def parse_ocpp_message(data: Any, *, version: Any, response_action: str | None = None) -> dict[str, Any]:
    """Parse one extracted OCPP 1.6J/2.0.1 JSON application message."""
    return _parse_ocpp(data, _ocpp_version(version), response_action)


@_closed
def analyze_ocpp_handshake(metadata: Any, *, version: Any) -> dict[str, Any]:
    """Inventory supplied handshake/security metadata without asserting live controls."""
    selected = _ocpp_version(version)
    if not isinstance(metadata, Mapping):
        raise SecEvchargeV2GError("handshake metadata must be a mapping")
    expected = "ocpp1.6" if selected == "1.6J" else "ocpp2.0.1"
    subprotocol = metadata.get("subprotocol")
    if type(subprotocol) is not str or len(subprotocol) > 128:
        raise SecEvchargeV2GError("subprotocol must be bounded text")
    profile = metadata.get("security_profile")
    if profile is not None and (type(profile) is not int or profile not in (1, 2, 3)):
        raise SecEvchargeV2GError("security_profile must be 1, 2, 3, or omitted")
    for key in ("tls", "basic_auth", "mutual_tls"):
        if key in metadata and type(metadata[key]) is not bool:
            raise SecEvchargeV2GError(f"{key} must be boolean when supplied")
    issues: list[dict[str, Any]] = []
    if subprotocol != expected:
        issues.append({"code": "subprotocol_version_mismatch", "expected": expected, "actual": subprotocol})
    if profile == 1 and metadata.get("tls") is True:
        issues.append({"code": "profile_transport_mismatch", "detail": "profile 1 is unencrypted"})
    if profile in (2, 3) and metadata.get("tls") is False:
        issues.append({"code": "profile_transport_mismatch", "detail": "profiles 2/3 require TLS"})
    if profile in (1, 2) and metadata.get("basic_auth") is False:
        issues.append({"code": "profile_auth_mismatch", "detail": "profiles 1/2 require HTTP Basic authentication"})
    if profile == 3 and metadata.get("mutual_tls") is False:
        issues.append({"code": "profile_auth_mismatch", "detail": "profile 3 requires mutual TLS"})
    return {"version": selected, "expected_subprotocol": expected, "observed_subprotocol": subprotocol,
            "security_profile": profile, "issues": issues, "consistent": not issues,
            "limitations": ["Supplied handshake metadata is not proof that authentication or certificate validation succeeded."]}


@_closed
def analyze_ocpp_transcript(records: Any, *, version: Any,
                            handshake: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Correlate extracted bidirectional OCPP messages and outstanding CALL state."""
    selected = _ocpp_version(version)
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise SecEvchargeV2GError("records must be a sequence of message mappings")
    if not 1 <= len(records) <= MAX_TRANSCRIPT:
        raise SecEvchargeV2GError("transcript record count is outside the configured bound")
    pending: dict[tuple[str, str], dict[str, Any]] = {}
    pending_by_direction = {"station_to_csms": set(), "csms_to_station": set()}
    seen_by_direction = {"station_to_csms": set(), "csms_to_station": set()}
    messages: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    transcript_bytes = 0
    for index, row in enumerate(records):
        if not isinstance(row, Mapping):
            raise SecEvchargeV2GError(f"record {index} must be a mapping")
        direction = row.get("direction")
        if direction not in pending_by_direction:
            raise SecEvchargeV2GError(f"record {index} has an invalid direction")
        if "message" not in row:
            raise SecEvchargeV2GError(f"record {index} lacks message")
        raw_message = row["message"]
        if type(raw_message) is str:
            transcript_bytes += len(raw_message.encode("utf-8"))
        elif isinstance(raw_message, (bytes, bytearray, memoryview)):
            transcript_bytes += len(raw_message)
        else:
            raise SecEvchargeV2GError(f"record {index} message must be JSON bytes or text")
        if transcript_bytes > MAX_TRANSCRIPT_BYTES:
            raise SecEvchargeV2GError("OCPP transcript exceeds the aggregate byte cap")
        parsed = _parse_ocpp(raw_message, selected, None)
        unique_id = parsed["unique_id"]
        if parsed["kind"] == "CALL":
            key = (direction, unique_id)
            duplicate_live = key in pending
            if duplicate_live:
                issues.append({"code": "duplicate_live_unique_id", "index": index, "unique_id": unique_id})
            elif unique_id in seen_by_direction[direction]:
                issues.append({"code": "reused_unique_id", "index": index,
                               "direction": direction, "unique_id": unique_id})
            if pending_by_direction[direction]:
                issues.append({"code": "multiple_outstanding_calls", "index": index,
                               "direction": direction, "severity": "error"})
            seen_by_direction[direction].add(unique_id)
            # OCPP unique IDs are scoped to the sender. Preserve a same-sender
            # live request while permitting the peer to use the same ID.
            if not duplicate_live:
                pending[key] = {"direction": direction, "action": parsed["action"], "index": index}
                pending_by_direction[direction].add(unique_id)
        else:
            request_direction = (
                "station_to_csms" if direction == "csms_to_station" else "csms_to_station"
            )
            key = (request_direction, unique_id)
            request = pending.get(key)
            if request is None:
                if (direction, unique_id) in pending:
                    issues.append({"code": "response_direction_mismatch", "index": index,
                                   "expected": request_direction})
                else:
                    issues.append({"code": "orphan_response", "index": index,
                                   "unique_id": unique_id})
            else:
                if parsed["kind"] == "CALLRESULT":
                    parsed = _parse_ocpp(raw_message, selected, request["action"])
                pending.pop(key, None)
                pending_by_direction[request["direction"]].discard(unique_id)
                parsed["response_action"] = request["action"]
                parsed["request_index"] = request["index"]
        parsed["index"] = index
        parsed["direction"] = direction
        messages.append(parsed)
    for (direction, unique_id), request in sorted(
            pending.items(), key=lambda item: item[1]["index"]):
        issues.append({"code": "unanswered_call", "severity": "note",
                       "direction": direction, "unique_id": unique_id,
                       "request_index": request["index"], "action": request["action"]})
    handshake_result = analyze_ocpp_handshake(handshake, version=selected) if handshake is not None else None
    if handshake_result is not None:
        issues.extend({"code": "handshake_" + issue["code"], **{k: v for k, v in issue.items() if k != "code"}}
                      for issue in handshake_result["issues"])
    hard = [issue for issue in issues if issue.get("severity") not in ("note", "warning")]
    return {"version": selected, "messages": messages, "issues": issues,
            "correlation_valid": not hard, "handshake": handshake_result,
            "limitations": ["Messages must already be extracted from WebSocket; raw framing is handled elsewhere."]}


def _read(path: str, maximum: int) -> bytes:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(maximum + 1)
    except (OSError, ValueError, TypeError) as exc:
        raise SecEvchargeV2GError(f"cannot read input file: {exc}") from exc
    if len(data) > maximum:
        raise SecEvchargeV2GError("input file exceeds the configured cap")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    v2g = sub.add_parser("v2gtp", help="parse one exact V2GTP frame")
    v2g.add_argument("file")
    v2g.add_argument("--protocol", choices=("iso2", "iso20"))
    ocpp = sub.add_parser("ocpp", help="parse one extracted OCPP JSON message")
    ocpp.add_argument("file")
    ocpp.add_argument("--version", required=True, choices=("1.6J", "2.0.1"))
    ocpp.add_argument("--response-action")
    catalog = sub.add_parser("iso-catalog", help="show the generation-specific ISO message catalog")
    catalog.add_argument("generation", choices=("iso2", "iso20"))
    catalog.add_argument("--amendment-1", action="store_true")
    iso_trace = sub.add_parser("iso-transcript", help="check caller-decoded ISO message JSON")
    iso_trace.add_argument("file")
    iso_trace.add_argument("--generation", required=True, choices=("iso2", "iso20"))
    pnc = sub.add_parser("pnc", help="check supplied Plug & Charge evidence JSON")
    pnc.add_argument("file")
    pnc.add_argument("--generation", required=True, choices=("iso2", "iso20"))
    ocpp_trace = sub.add_parser("ocpp-transcript", help="correlate extracted OCPP message JSON")
    ocpp_trace.add_argument("file")
    ocpp_trace.add_argument("--version", required=True, choices=("1.6J", "2.0.1"))
    handshake = sub.add_parser("ocpp-handshake", help="inventory supplied OCPP handshake JSON")
    handshake.add_argument("file")
    handshake.add_argument("--version", required=True, choices=("1.6J", "2.0.1"))
    try:
        args = parser.parse_args(argv)
        if args.command == "v2gtp":
            result = parse_v2gtp(_read(args.file, MAX_FRAME), protocol=args.protocol)
        elif args.command == "ocpp":
            result = parse_ocpp_message(_read(args.file, MAX_JSON), version=args.version,
                                        response_action=args.response_action)
        elif args.command == "iso-catalog":
            result = iso15118_catalog(args.generation, amendment_1=args.amendment_1)
        elif args.command == "iso-transcript":
            result = analyze_iso15118_transcript(_load_json(_read(args.file, MAX_JSON)),
                                                  generation=args.generation)
        elif args.command == "pnc":
            result = analyze_pnc_evidence(
                _load_json(_read(args.file, MAX_JSON)), generation=args.generation
            )
        elif args.command == "ocpp-transcript":
            result = analyze_ocpp_transcript(_load_json(_read(args.file, MAX_JSON)), version=args.version)
        else:
            result = analyze_ocpp_handshake(_load_json(_read(args.file, MAX_JSON)), version=args.version)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (SecEvchargeV2GError, OSError, ValueError, TypeError) as exc:
        print(f"sec_evcharge_v2g: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"sec_evcharge_v2g: analysis failed: {type(exc).__name__}: {str(exc)[:240]}",
            file=sys.stderr,
        )
        return 2


__all__ = [
    "SecEvchargeV2GError", "V2GTP_PAYLOAD_TYPES", "ISO2_MESSAGES",
    "ISO20_MESSAGE_FAMILIES", "ISO20_SERVICES", "PNC_ROLES", "PNC_CEREMONIES",
    "PNC_CEREMONY",
    "OCPP16_CORE_ACTIONS", "OCPP16_SECURITY_ACTIONS", "OCPP201_ACTIONS",
    "OCPP16_ERRORS", "OCPP201_ERRORS", "parse_v2gtp", "parse_wired_sdp",
    "inspect_exi_header", "iso15118_catalog", "analyze_iso15118_transcript",
    "analyze_pnc_evidence", "parse_ocpp_message", "analyze_ocpp_transcript",
    "analyze_ocpp_handshake", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
