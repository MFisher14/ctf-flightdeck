#!/usr/bin/env python3
"""Offline industrial application-protocol and HMI/historian analysis.

This module consumes supplied bytes/files only. It implements bounded decoders for
OPC UA Binary/TCP chunks, EtherCAT datagrams and CoE/FoE mailboxes, PROFINET
DCE/RPC/NDR blocks, and DNP3 Secure Authentication objects/state. It also inventories
HMI project archives and reads historian CSV/SQLite artifacts read-only. It has no
socket, interface, RPC client, subprocess, controller, or active-probing path.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import io
import json
import math
import re
import sqlite3
import statistics
import struct
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

MAX_INPUT = 64 * 1024 * 1024
MAX_FRAME = 16 * 1024 * 1024
MAX_ITEMS = 250_000
MAX_DEPTH = 32
MAX_STRING = 8 * 1024 * 1024
MAX_TABLES = 1_000
MAX_SQL_ROWS = 2_000
MAX_COLUMNS = 512
MAX_ARCHIVE_FILES = 50_000
MAX_ARCHIVE_TOTAL = 512 * 1024 * 1024


class ParseError(ValueError):
    """Supplied evidence is malformed, ambiguous, or exceeds a safety bound."""


def _blob(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("artifact must be bytes-like")
    data = bytes(value)
    if len(data) > MAX_INPUT:
        raise ParseError("artifact exceeds input cap")
    return data


def _need(data: bytes, offset: int, length: int, label: str) -> None:
    if length < 0 or offset < 0 or offset + length > len(data):
        raise ParseError(f"truncated {label}")


def _finding(kind: str, severity: str, detail: str, **evidence: Any) -> dict[str, Any]:
    out = {"kind": kind, "severity": severity, "detail": detail}
    out.update({key: value for key, value in evidence.items() if value is not None})
    return out


def _sort_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    unique = {json.dumps(item, sort_keys=True, default=str): item for item in findings}
    return sorted(unique.values(), key=lambda item: (-rank.get(str(item.get("severity")), 0),
                                                      str(item.get("kind")), str(item.get("path", ""))))


# --------------------------------------------------------------------------- OPC UA Binary/TCP

OPCUA_MESSAGE_TYPES = {"HEL", "ACK", "ERR", "RHE", "OPN", "MSG", "CLO"}
OPCUA_SERVICE_IDS = {
    422: "FindServersRequest", 425: "FindServersResponse", 428: "GetEndpointsRequest", 431: "GetEndpointsResponse",
    446: "OpenSecureChannelRequest", 449: "OpenSecureChannelResponse",
    461: "CreateSessionRequest", 464: "CreateSessionResponse", 467: "ActivateSessionRequest",
    470: "ActivateSessionResponse", 473: "CloseSessionRequest", 476: "CloseSessionResponse",
    527: "BrowseRequest", 530: "BrowseResponse", 631: "ReadRequest", 634: "ReadResponse",
    673: "WriteRequest", 676: "WriteResponse", 712: "CallRequest", 715: "CallResponse",
    751: "CreateMonitoredItemsRequest", 754: "CreateMonitoredItemsResponse",
    787: "CreateSubscriptionRequest", 790: "CreateSubscriptionResponse",
    826: "PublishRequest", 829: "PublishResponse", 845: "DeleteSubscriptionsRequest",
    848: "DeleteSubscriptionsResponse",
}
OPCUA_REQUEST_IDS = {ident for ident, name in OPCUA_SERVICE_IDS.items() if name.endswith("Request")}
OPCUA_VARIANT_TYPES = {
    0: "Null", 1: "Boolean", 2: "SByte", 3: "Byte", 4: "Int16", 5: "UInt16", 6: "Int32",
    7: "UInt32", 8: "Int64", 9: "UInt64", 10: "Float", 11: "Double", 12: "String",
    13: "DateTime", 14: "Guid", 15: "ByteString", 16: "XmlElement", 17: "NodeId",
    18: "ExpandedNodeId", 19: "StatusCode", 20: "QualifiedName", 21: "LocalizedText",
    22: "ExtensionObject", 23: "DataValue", 24: "Variant", 25: "DiagnosticInfo",
}


def _ua_i32(data: bytes, offset: int, label: str) -> tuple[int, int]:
    _need(data, offset, 4, label)
    return struct.unpack_from("<i", data, offset)[0], offset + 4


def _ua_u32(data: bytes, offset: int, label: str) -> tuple[int, int]:
    _need(data, offset, 4, label)
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def _ua_i64(data: bytes, offset: int, label: str) -> tuple[int, int]:
    _need(data, offset, 8, label)
    return struct.unpack_from("<q", data, offset)[0], offset + 8


def _ua_string(data: bytes, offset: int, label: str = "OPC UA string") -> tuple[str | None, int]:
    length, offset = _ua_i32(data, offset, label + " length")
    if length == -1:
        return None, offset
    if length < -1 or length > MAX_STRING:
        raise ParseError(f"invalid {label} length")
    _need(data, offset, length, label)
    raw = data[offset:offset + length]
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ParseError(f"invalid UTF-8 in {label}") from exc
    return value, offset + length


def _ua_bytestring(data: bytes, offset: int, label: str = "OPC UA ByteString") -> tuple[bytes | None, int]:
    length, offset = _ua_i32(data, offset, label + " length")
    if length == -1:
        return None, offset
    if length < -1 or length > MAX_STRING:
        raise ParseError(f"invalid {label} length")
    _need(data, offset, length, label)
    return data[offset:offset + length], offset + length


def _ua_datetime(value: int) -> dict[str, Any]:
    out: dict[str, Any] = {"filetime_100ns": value}
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        out["iso"] = (epoch + timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, ValueError):
        pass
    return out


def parse_opcua_nodeid(data: bytes, offset: int = 0, *, expanded: bool = False) -> tuple[dict[str, Any], int]:
    data = _blob(data)
    _need(data, offset, 1, "OPC UA NodeId encoding")
    encoding = data[offset]
    offset += 1
    kind = encoding & 0x3F
    if kind == 0:
        _need(data, offset, 1, "two-byte NodeId")
        namespace, identifier, id_type = 0, data[offset], "numeric"
        offset += 1
    elif kind == 1:
        _need(data, offset, 3, "four-byte NodeId")
        namespace, identifier, id_type = data[offset], struct.unpack_from("<H", data, offset + 1)[0], "numeric"
        offset += 3
    elif kind == 2:
        _need(data, offset, 6, "numeric NodeId")
        namespace, identifier, id_type = struct.unpack_from("<H", data, offset)[0], struct.unpack_from("<I", data, offset + 2)[0], "numeric"
        offset += 6
    elif kind == 3:
        _need(data, offset, 2, "string NodeId namespace")
        namespace = struct.unpack_from("<H", data, offset)[0]
        identifier, offset = _ua_string(data, offset + 2, "NodeId string")
        id_type = "string"
    elif kind == 4:
        _need(data, offset, 18, "GUID NodeId")
        namespace = struct.unpack_from("<H", data, offset)[0]
        identifier = str(uuid.UUID(bytes_le=data[offset + 2:offset + 18]))
        id_type = "guid"
        offset += 18
    elif kind == 5:
        _need(data, offset, 2, "ByteString NodeId namespace")
        namespace = struct.unpack_from("<H", data, offset)[0]
        raw, offset = _ua_bytestring(data, offset + 2, "NodeId ByteString")
        identifier, id_type = None if raw is None else raw.hex(), "bytes"
    else:
        raise ParseError(f"unsupported OPC UA NodeId encoding 0x{kind:02x}")
    result: dict[str, Any] = {"namespace": namespace, "type": id_type, "identifier": identifier}
    if expanded or encoding & 0xC0:
        if encoding & 0x80:
            result["namespace_uri"], offset = _ua_string(data, offset, "ExpandedNodeId namespace URI")
        if encoding & 0x40:
            result["server_index"], offset = _ua_u32(data, offset, "ExpandedNodeId server index")
    return result, offset


def _ua_qualified_name(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    _need(data, offset, 2, "QualifiedName namespace")
    namespace = struct.unpack_from("<H", data, offset)[0]
    name, offset = _ua_string(data, offset + 2, "QualifiedName")
    return {"namespace": namespace, "name": name}, offset


def _ua_localized_text(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    _need(data, offset, 1, "LocalizedText encoding")
    mask = data[offset]
    offset += 1
    out: dict[str, Any] = {"encoding_mask": mask}
    if mask & 1:
        out["locale"], offset = _ua_string(data, offset, "LocalizedText locale")
    if mask & 2:
        out["text"], offset = _ua_string(data, offset, "LocalizedText text")
    if mask & ~3:
        raise ParseError("unsupported LocalizedText encoding bits")
    return out, offset


def _ua_extension_object(data: bytes, offset: int, depth: int) -> tuple[dict[str, Any], int]:
    type_id, offset = parse_opcua_nodeid(data, offset)
    _need(data, offset, 1, "ExtensionObject encoding")
    encoding = data[offset]
    offset += 1
    out: dict[str, Any] = {"type_id": type_id, "encoding": encoding}
    if encoding in (1, 2):
        raw, offset = _ua_bytestring(data, offset, "ExtensionObject body")
        out["body"] = None if raw is None else raw.hex()
    elif encoding != 0:
        raise ParseError("unsupported ExtensionObject encoding")
    return out, offset


def _ua_diagnostic_info(data: bytes, offset: int, depth: int) -> tuple[dict[str, Any], int]:
    if depth > MAX_DEPTH:
        raise ParseError("OPC UA diagnostic nesting cap exceeded")
    _need(data, offset, 1, "DiagnosticInfo mask")
    mask = data[offset]
    offset += 1
    out: dict[str, Any] = {"encoding_mask": mask}
    for bit, name in ((1, "symbolic_id"), (2, "namespace_uri"), (4, "locale"), (8, "localized_text")):
        if mask & bit:
            value, offset = _ua_i32(data, offset, f"DiagnosticInfo {name}")
            out[name] = value
    if mask & 0x10:
        out["additional_info"], offset = _ua_string(data, offset, "DiagnosticInfo additional info")
    if mask & 0x20:
        out["inner_status_code"], offset = _ua_u32(data, offset, "DiagnosticInfo inner status")
    if mask & 0x40:
        out["inner_diagnostic"], offset = _ua_diagnostic_info(data, offset, depth + 1)
    if mask & 0x80:
        raise ParseError("reserved DiagnosticInfo encoding bit is set")
    return out, offset


def parse_opcua_datavalue(data: bytes, offset: int = 0, *, depth: int = 0) -> tuple[dict[str, Any], int]:
    if depth > MAX_DEPTH:
        raise ParseError("OPC UA DataValue nesting cap exceeded")
    _need(data, offset, 1, "DataValue encoding")
    mask = data[offset]
    offset += 1
    out: dict[str, Any] = {"encoding_mask": mask}
    if mask & 1:
        out["value"], offset = parse_opcua_variant(data, offset, depth=depth + 1)
    if mask & 2:
        out["status_code"], offset = _ua_u32(data, offset, "DataValue status")
    if mask & 4:
        value, offset = _ua_i64(data, offset, "DataValue source timestamp")
        out["source_timestamp"] = _ua_datetime(value)
    if mask & 8:
        value, offset = _ua_i64(data, offset, "DataValue server timestamp")
        out["server_timestamp"] = _ua_datetime(value)
    if mask & 0x10:
        _need(data, offset, 2, "DataValue source picoseconds")
        out["source_picoseconds"] = struct.unpack_from("<H", data, offset)[0]
        offset += 2
    if mask & 0x20:
        _need(data, offset, 2, "DataValue server picoseconds")
        out["server_picoseconds"] = struct.unpack_from("<H", data, offset)[0]
        offset += 2
    if mask & 0xC0:
        raise ParseError("reserved DataValue encoding bits are set")
    return out, offset


def _ua_scalar(data: bytes, offset: int, type_id: int, depth: int) -> tuple[Any, int]:
    formats = {
        1: ("<?", 1), 2: ("<b", 1), 3: ("<B", 1), 4: ("<h", 2), 5: ("<H", 2),
        6: ("<i", 4), 7: ("<I", 4), 8: ("<q", 8), 9: ("<Q", 8), 10: ("<f", 4), 11: ("<d", 8),
    }
    if type_id == 0:
        return None, offset
    if type_id in formats:
        fmt, size = formats[type_id]
        _need(data, offset, size, OPCUA_VARIANT_TYPES[type_id])
        return struct.unpack_from(fmt, data, offset)[0], offset + size
    if type_id == 12:
        return _ua_string(data, offset)
    if type_id == 13:
        value, offset = _ua_i64(data, offset, "DateTime")
        return _ua_datetime(value), offset
    if type_id == 14:
        _need(data, offset, 16, "GUID")
        return str(uuid.UUID(bytes_le=data[offset:offset + 16])), offset + 16
    if type_id == 15:
        value, offset = _ua_bytestring(data, offset)
        return None if value is None else value.hex(), offset
    if type_id == 16:
        return _ua_string(data, offset, "XmlElement")
    if type_id == 17:
        return parse_opcua_nodeid(data, offset)
    if type_id == 18:
        return parse_opcua_nodeid(data, offset, expanded=True)
    if type_id == 19:
        return _ua_u32(data, offset, "StatusCode")
    if type_id == 20:
        return _ua_qualified_name(data, offset)
    if type_id == 21:
        return _ua_localized_text(data, offset)
    if type_id == 22:
        return _ua_extension_object(data, offset, depth)
    if type_id == 23:
        return parse_opcua_datavalue(data, offset, depth=depth)
    if type_id == 24:
        return parse_opcua_variant(data, offset, depth=depth)
    if type_id == 25:
        return _ua_diagnostic_info(data, offset, depth)
    raise ParseError(f"unsupported OPC UA Variant type {type_id}")


def parse_opcua_variant(data: bytes, offset: int = 0, *, depth: int = 0) -> tuple[dict[str, Any], int]:
    data = _blob(data)
    if depth > MAX_DEPTH:
        raise ParseError("OPC UA Variant nesting cap exceeded")
    _need(data, offset, 1, "Variant encoding")
    encoding = data[offset]
    offset += 1
    type_id = encoding & 0x3F
    if type_id not in OPCUA_VARIANT_TYPES:
        raise ParseError(f"unknown OPC UA Variant type {type_id}")
    array = bool(encoding & 0x80)
    dimensions = bool(encoding & 0x40)
    if dimensions and not array:
        raise ParseError("Variant dimensions bit requires array bit")
    if array:
        count, offset = _ua_i32(data, offset, "Variant array length")
        if count == -1:
            value = None
        elif count < -1 or count > MAX_ITEMS:
            raise ParseError("invalid or excessive Variant array length")
        else:
            value = []
            for _ in range(count):
                item, offset = _ua_scalar(data, offset, type_id, depth + 1)
                value.append(item)
    else:
        value, offset = _ua_scalar(data, offset, type_id, depth + 1)
    out: dict[str, Any] = {"type_id": type_id, "type": OPCUA_VARIANT_TYPES[type_id], "array": array, "value": value}
    if dimensions:
        count, offset = _ua_i32(data, offset, "Variant dimension count")
        if count < 0 or count > 64:
            raise ParseError("invalid Variant dimension count")
        dims = []
        for _ in range(count):
            dimension, offset = _ua_i32(data, offset, "Variant dimension")
            if dimension < 0:
                raise ParseError("negative Variant dimension")
            dims.append(dimension)
        if value is not None and dims and math.prod(dims) != len(value):
            raise ParseError("Variant dimensions do not match array length")
        out["dimensions"] = dims
    return out, offset


def _opcua_request_header(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    token, offset = parse_opcua_nodeid(data, offset)
    timestamp, offset = _ua_i64(data, offset, "RequestHeader timestamp")
    request_handle, offset = _ua_u32(data, offset, "RequestHeader handle")
    diagnostics, offset = _ua_u32(data, offset, "RequestHeader diagnostics")
    audit, offset = _ua_string(data, offset, "RequestHeader audit entry")
    timeout, offset = _ua_u32(data, offset, "RequestHeader timeout")
    additional, offset = _ua_extension_object(data, offset, 0)
    return {"authentication_token": token, "timestamp": _ua_datetime(timestamp), "request_handle": request_handle,
            "return_diagnostics": diagnostics, "audit_entry_id": audit, "timeout_hint_ms": timeout,
            "additional_header": additional}, offset


def _opcua_response_header(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    timestamp, offset = _ua_i64(data, offset, "ResponseHeader timestamp")
    handle, offset = _ua_u32(data, offset, "ResponseHeader handle")
    status, offset = _ua_u32(data, offset, "ResponseHeader service result")
    diagnostic, offset = _ua_diagnostic_info(data, offset, 0)
    count, offset = _ua_i32(data, offset, "ResponseHeader string table count")
    if count < -1 or count > MAX_ITEMS:
        raise ParseError("invalid ResponseHeader string table count")
    strings = []
    for _ in range(max(count, 0)):
        item, offset = _ua_string(data, offset, "ResponseHeader string table item")
        strings.append(item)
    additional, offset = _ua_extension_object(data, offset, 0)
    return {"timestamp": _ua_datetime(timestamp), "request_handle": handle, "service_result": status,
            "service_diagnostics": diagnostic, "string_table": strings, "additional_header": additional}, offset


def _opcua_count(data: bytes, offset: int, label: str) -> tuple[int, int]:
    count, offset = _ua_i32(data, offset, label)
    if count < -1 or count > MAX_ITEMS:
        raise ParseError(f"invalid or excessive {label}")
    return max(count, 0), offset


def decode_opcua_service(data: bytes) -> dict[str, Any]:
    data = _blob(data)
    service_type, offset = parse_opcua_nodeid(data, 0)
    service_id = service_type["identifier"] if service_type["namespace"] == 0 and service_type["type"] == "numeric" else None
    name = OPCUA_SERVICE_IDS.get(service_id, f"UnknownService({service_id})")
    out: dict[str, Any] = {"type_id": service_type, "service_id": service_id, "service": name}
    if service_id in OPCUA_REQUEST_IDS:
        out["request_header"], offset = _opcua_request_header(data, offset)
    elif name.endswith("Response"):
        out["response_header"], offset = _opcua_response_header(data, offset)
    else:
        out["body"] = data[offset:].hex()
        return out
    if service_id == 446:
        client_version, offset = _ua_u32(data, offset, "OpenSecureChannel client protocol version")
        request_type, offset = _ua_u32(data, offset, "OpenSecureChannel request type")
        security_mode, offset = _ua_u32(data, offset, "OpenSecureChannel security mode")
        nonce, offset = _ua_bytestring(data, offset, "OpenSecureChannel client nonce")
        lifetime, offset = _ua_u32(data, offset, "OpenSecureChannel requested lifetime")
        out.update(client_protocol_version=client_version, request_type=request_type,
                   message_security_mode=security_mode, client_nonce=None if nonce is None else nonce.hex(),
                   requested_lifetime_ms=lifetime)
    elif service_id == 631:
        _need(data, offset, 12, "ReadRequest parameters")
        out["max_age"] = struct.unpack_from("<d", data, offset)[0]
        out["timestamps_to_return"] = struct.unpack_from("<I", data, offset + 8)[0]
        offset += 12
        count, offset = _opcua_count(data, offset, "ReadRequest node count")
        nodes = []
        for _ in range(count):
            node, offset = parse_opcua_nodeid(data, offset)
            attribute, offset = _ua_u32(data, offset, "ReadValueId attribute")
            index_range, offset = _ua_string(data, offset, "ReadValueId index range")
            encoding, offset = _ua_qualified_name(data, offset)
            nodes.append({"node_id": node, "attribute_id": attribute, "index_range": index_range, "data_encoding": encoding})
        out["nodes_to_read"] = nodes
    elif service_id == 673:
        count, offset = _opcua_count(data, offset, "WriteRequest node count")
        nodes = []
        for _ in range(count):
            node, offset = parse_opcua_nodeid(data, offset)
            attribute, offset = _ua_u32(data, offset, "WriteValue attribute")
            index_range, offset = _ua_string(data, offset, "WriteValue index range")
            value, offset = parse_opcua_datavalue(data, offset)
            nodes.append({"node_id": node, "attribute_id": attribute, "index_range": index_range, "value": value})
        out["nodes_to_write"] = nodes
    elif service_id == 634:
        count, offset = _opcua_count(data, offset, "ReadResponse result count")
        values = []
        for _ in range(count):
            value, offset = parse_opcua_datavalue(data, offset)
            values.append(value)
        out["results"] = values
    elif service_id == 676:
        count, offset = _opcua_count(data, offset, "WriteResponse result count")
        results = []
        for _ in range(count):
            status, offset = _ua_u32(data, offset, "WriteResponse status")
            results.append(status)
        out["results"] = results
    elif service_id == 712:
        count, offset = _opcua_count(data, offset, "CallRequest method count")
        calls = []
        for _ in range(count):
            object_id, offset = parse_opcua_nodeid(data, offset)
            method_id, offset = parse_opcua_nodeid(data, offset)
            arg_count, offset = _opcua_count(data, offset, "CallMethod argument count")
            args = []
            for _ in range(arg_count):
                argument, offset = parse_opcua_variant(data, offset)
                args.append(argument)
            calls.append({"object_id": object_id, "method_id": method_id, "arguments": args})
        out["methods_to_call"] = calls
    else:
        out["body"] = data[offset:].hex()
        offset = len(data)
    if offset != len(data):
        out["trailing"] = data[offset:].hex()
    return out


def iter_opcua_chunks(data: bytes) -> Iterable[bytes]:
    data = _blob(data)
    offset = 0
    while offset < len(data):
        _need(data, offset, 8, "OPC UA TCP header")
        message_type = data[offset:offset + 3].decode("ascii", "replace")
        if message_type not in OPCUA_MESSAGE_TYPES:
            raise ParseError(f"unknown OPC UA message type {message_type!r}")
        chunk_type = chr(data[offset + 3])
        if chunk_type not in {"F", "C", "A"}:
            raise ParseError(f"unknown OPC UA chunk type {chunk_type!r}")
        size = struct.unpack_from("<I", data, offset + 4)[0]
        if size < 8 or size > MAX_FRAME:
            raise ParseError("invalid OPC UA message size")
        _need(data, offset, size, "OPC UA chunk")
        yield data[offset:offset + size]
        offset += size


def parse_opcua_chunk(frame: bytes, *, channel_policies: dict[int, str] | None = None) -> dict[str, Any]:
    frame = _blob(frame)
    if len(frame) < 8:
        raise ParseError("truncated OPC UA chunk")
    try:
        message_type = frame[:3].decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise ParseError("invalid OPC UA TCP header") from exc
    chunk_type = chr(frame[3])
    size = struct.unpack_from("<I", frame, 4)[0]
    if message_type not in OPCUA_MESSAGE_TYPES or chunk_type not in {"F", "C", "A"} or size != len(frame):
        raise ParseError("invalid OPC UA TCP header")
    out: dict[str, Any] = {"message_type": message_type, "chunk_type": chunk_type, "size": size}
    offset = 8
    if message_type in {"HEL", "ACK"}:
        _need(frame, offset, 20, f"OPC UA {message_type}")
        fields = struct.unpack_from("<IIIII", frame, offset)
        out.update(protocol_version=fields[0], receive_buffer_size=fields[1], send_buffer_size=fields[2],
                   max_message_size=fields[3], max_chunk_count=fields[4])
        offset += 20
        if message_type == "HEL":
            out["endpoint_url"], offset = _ua_string(frame, offset, "HEL endpoint URL")
    elif message_type == "ERR":
        out["error"], offset = _ua_u32(frame, offset, "ERR code")
        out["reason"], offset = _ua_string(frame, offset, "ERR reason")
    elif message_type == "RHE":
        out["server_uri"], offset = _ua_string(frame, offset, "RHE server URI")
        out["endpoint_url"], offset = _ua_string(frame, offset, "RHE endpoint URL")
    else:
        channel, offset = _ua_u32(frame, offset, "SecureConversation channel id")
        out["secure_channel_id"] = channel
        policy = None
        if message_type == "OPN":
            policy, offset = _ua_string(frame, offset, "security policy URI")
            certificate, offset = _ua_bytestring(frame, offset, "sender certificate")
            thumbprint, offset = _ua_bytestring(frame, offset, "receiver thumbprint")
            out["security_header"] = {
                "policy_uri": policy,
                "sender_certificate_length": None if certificate is None else len(certificate),
                "sender_certificate_sha256": None if not certificate else hashlib.sha256(certificate).hexdigest(),
                "receiver_thumbprint": None if thumbprint is None else thumbprint.hex(),
            }
        else:
            token, offset = _ua_u32(frame, offset, "symmetric security token id")
            out["security_header"] = {"token_id": token}
            policy = (channel_policies or {}).get(channel)
        none_policy = policy is not None and (policy.endswith("#None") or policy == "None")
        if none_policy:
            sequence, offset = _ua_u32(frame, offset, "SequenceHeader sequence")
            request, offset = _ua_u32(frame, offset, "SequenceHeader request id")
            out["sequence_number"] = sequence
            out["request_id"] = request
            out["body_fragment"] = frame[offset:].hex()
        else:
            out["protected_payload"] = frame[offset:].hex()
            out["payload_decoded"] = False
    if offset != len(frame) and message_type in {"HEL", "ACK", "ERR", "RHE"}:
        raise ParseError("trailing OPC UA handshake bytes")
    return out


def analyze_opcua_stream(data: bytes) -> dict[str, Any]:
    policies: dict[int, str] = {}
    chunks, messages, findings = [], [], []
    pending: dict[tuple[str, int, int], bytearray] = {}
    last_sequence: dict[int, int] = {}
    for raw in iter_opcua_chunks(data):
        chunk = parse_opcua_chunk(raw, channel_policies=policies)
        chunks.append(chunk)
        channel = int(chunk.get("secure_channel_id", 0))
        policy = (chunk.get("security_header") or {}).get("policy_uri")
        if policy is not None:
            policies[channel] = policy
            if policy.endswith("#None") or policy == "None":
                findings.append(_finding("opcua-security-none", "high", "OPC UA SecureConversation uses SecurityPolicy None",
                                         secure_channel_id=channel))
            if not (chunk.get("security_header") or {}).get("sender_certificate_length") and not (policy.endswith("#None") or policy == "None"):
                findings.append(_finding("opcua-certificate-absent", "medium", "secure policy header has no sender certificate",
                                         secure_channel_id=channel, policy=policy))
        if chunk["chunk_type"] == "A":
            findings.append(_finding("opcua-aborted-chunk", "medium", "OPC UA message chunk was aborted",
                                     secure_channel_id=channel))
        if "sequence_number" in chunk:
            sequence = int(chunk["sequence_number"])
            previous = last_sequence.get(channel)
            if previous is not None and sequence != (previous + 1) & 0xFFFFFFFF:
                findings.append(_finding("opcua-sequence-gap", "medium", "OPC UA channel sequence is not contiguous",
                                         secure_channel_id=channel, previous=previous, sequence=sequence))
            last_sequence[channel] = sequence
            key = (chunk["message_type"], channel, int(chunk["request_id"]))
            body = bytes.fromhex(chunk["body_fragment"])
            pending.setdefault(key, bytearray()).extend(body)
            if chunk["chunk_type"] == "F":
                assembled = bytes(pending.pop(key))
                message: dict[str, Any] = {"message_type": key[0], "secure_channel_id": channel,
                                           "request_id": key[2], "body": assembled.hex()}
                try:
                    message["service"] = decode_opcua_service(assembled)
                    service_name = message["service"]["service"]
                    if service_name == "WriteRequest":
                        findings.append(_finding("opcua-write", "high", "OPC UA Write service request is present",
                                                 secure_channel_id=channel, request_id=key[2]))
                    elif service_name == "CallRequest":
                        findings.append(_finding("opcua-method-call", "high", "OPC UA method Call request is present",
                                                 secure_channel_id=channel, request_id=key[2]))
                    if service_name == "OpenSecureChannelRequest" and message["service"].get("message_security_mode") == 1:
                        findings.append(_finding("opcua-message-mode-none", "high", "OpenSecureChannel requests MessageSecurityMode None",
                                                 secure_channel_id=channel, request_id=key[2]))
                except ParseError as exc:
                    message["service_error"] = str(exc)
                messages.append(message)
        endpoint = chunk.get("endpoint_url")
        if isinstance(endpoint, str) and re.search(r"(?i)opc\.tcp://(?:0\.0\.0\.0|\*|localhost|127\.0\.0\.1)", endpoint):
            findings.append(_finding("opcua-endpoint-local-or-wildcard", "low", "HEL/RHE endpoint uses a local or wildcard host",
                                     endpoint=endpoint))
    for key, body in pending.items():
        findings.append(_finding("opcua-incomplete-message", "medium", "continued OPC UA chunks have no final chunk",
                                 secure_channel_id=key[1], request_id=key[2], bytes=len(body)))
    return {"protocol": "opcua", "chunks": chunks, "messages": messages,
            "channel_policies": policies, "findings": _sort_findings(findings)}


# --------------------------------------------------------------------------- EtherCAT / mailbox / CoE / FoE

ETHERCAT_COMMANDS = {
    0x00: "NOP", 0x01: "APRD", 0x02: "APWR", 0x03: "APRW", 0x04: "FPRD", 0x05: "FPWR",
    0x06: "FPRW", 0x07: "BRD", 0x08: "BWR", 0x09: "BRW", 0x0A: "LRD", 0x0B: "LWR",
    0x0C: "LRW", 0x0D: "ARMW", 0x0E: "FRMW",
}
ETHERCAT_STATES = {1: "INIT", 2: "PREOP", 3: "BOOT", 4: "SAFEOP", 8: "OP"}
MAILBOX_TYPES = {0: "Error", 1: "AoE", 2: "EoE", 3: "CoE", 4: "FoE", 5: "SoE", 15: "VoE"}
COE_SERVICES = {1: "Emergency", 2: "SDO Request", 3: "SDO Response", 4: "TxPDO", 5: "RxPDO",
                6: "TxPDO Remote", 7: "RxPDO Remote", 8: "SDO Information"}
FOE_OPCODES = {1: "Read Request", 2: "Write Request", 3: "Data", 4: "Ack", 5: "Error", 6: "Busy"}


def parse_ethercat_coe(data: bytes) -> dict[str, Any]:
    data = _blob(data)
    _need(data, 0, 2, "CoE header")
    header = struct.unpack_from("<H", data, 0)[0]
    service = (header >> 12) & 0xF
    out: dict[str, Any] = {"protocol": "CoE", "number": header & 0x1FF, "service": service,
                           "service_name": COE_SERVICES.get(service, "Unknown")}
    payload = data[2:]
    if service in {2, 3}:
        _need(payload, 0, 1, "CoE SDO command")
        command = payload[0]
        out["command"] = command
        out["command_specifier"] = (command >> 5) & 7
        if len(payload) >= 4:
            out["index"] = struct.unpack_from("<H", payload, 1)[0]
            out["subindex"] = payload[3]
            expedited, size_indicated = bool(command & 2), bool(command & 1)
            out.update(expedited=expedited, size_indicated=size_indicated)
            if expedited:
                unused = (command >> 2) & 3 if size_indicated else 0
                if unused > 3:
                    raise ParseError("invalid CoE expedited unused-byte count")
                out["value"] = payload[4:8 - unused].hex() if len(payload) >= 8 - unused else payload[4:].hex()
            elif len(payload) > 4:
                declared = struct.unpack_from("<I", payload, 4)[0] if size_indicated and len(payload) >= 8 else None
                out["declared_size"] = declared
                out["data"] = payload[8:].hex() if declared is not None else payload[4:].hex()
        if out["command_specifier"] == 4 and len(payload) >= 8:
            out["abort_code"] = struct.unpack_from("<I", payload, 4)[0]
    elif service == 1 and len(payload) >= 8:
        out["emergency_code"] = struct.unpack_from("<H", payload, 0)[0]
        out["error_register"] = payload[2]
        out["diagnostic"] = payload[3:8].hex()
    else:
        out["payload"] = payload.hex()
    return out


def parse_ethercat_foe(data: bytes) -> dict[str, Any]:
    data = _blob(data)
    _need(data, 0, 6, "FoE header")
    opcode = struct.unpack_from("<H", data, 0)[0]
    value = struct.unpack_from("<I", data, 2)[0]
    out: dict[str, Any] = {"protocol": "FoE", "opcode": opcode, "opcode_name": FOE_OPCODES.get(opcode, "Unknown")}
    body = data[6:]
    if opcode in {1, 2}:
        out["password"] = value
        out["filename"] = body.rstrip(b"\0").decode("utf-8", "replace")
    elif opcode == 3:
        out["packet_number"] = value
        out["data"] = body.hex()
    elif opcode == 4:
        out["packet_number"] = value
    elif opcode == 5:
        out["error_code"] = value
        out["error_text"] = body.rstrip(b"\0").decode("utf-8", "replace")
    elif opcode == 6:
        out["done"] = value
        if len(body) >= 4:
            out["entire"] = struct.unpack_from("<H", body, 0)[0]
            out["todo"] = struct.unpack_from("<H", body, 2)[0]
    else:
        out["value"] = value
        out["payload"] = body.hex()
    return out


def parse_ethercat_mailbox(data: bytes) -> dict[str, Any]:
    data = _blob(data)
    _need(data, 0, 6, "EtherCAT mailbox header")
    length, address = struct.unpack_from("<HH", data, 0)
    channel_priority, type_counter = data[4], data[5]
    if length > MAX_FRAME or 6 + length != len(data):
        raise ParseError("EtherCAT mailbox length mismatch")
    mailbox_type = type_counter & 0x0F
    payload = data[6:]
    out: dict[str, Any] = {"length": length, "address": address, "channel": channel_priority & 0x3F,
                           "priority": channel_priority >> 6, "counter": (type_counter >> 4) & 7,
                           "unsupported": bool(type_counter & 0x80), "type": mailbox_type,
                           "type_name": MAILBOX_TYPES.get(mailbox_type, "Unknown")}
    if mailbox_type == 3:
        out["coe"] = parse_ethercat_coe(payload)
    elif mailbox_type == 4:
        out["foe"] = parse_ethercat_foe(payload)
    else:
        out["payload"] = payload.hex()
    return out


def parse_ethercat_frame(data: bytes, *, ethernet: bool | None = None) -> dict[str, Any]:
    data = _blob(data)
    offset = 0
    if ethernet is True or (ethernet is None and len(data) >= 14 and data[12:14] in {b"\x88\xa4", b"\x81\x00"}):
        _need(data, 0, 14, "Ethernet header")
        ethertype = struct.unpack_from(">H", data, 12)[0]
        offset = 14
        if ethertype == 0x8100:
            _need(data, 14, 4, "VLAN header")
            ethertype = struct.unpack_from(">H", data, 16)[0]
            offset = 18
        if ethertype != 0x88A4:
            raise ParseError("Ethernet frame is not EtherCAT")
    _need(data, offset, 2, "EtherCAT frame header")
    header = struct.unpack_from("<H", data, offset)[0]
    length, frame_type = header & 0x07FF, (header >> 12) & 0xF
    if frame_type != 1:
        raise ParseError(f"unsupported EtherCAT frame type {frame_type}")
    if length > MAX_FRAME or offset + 2 + length != len(data):
        raise ParseError("EtherCAT frame length mismatch")
    cursor, end = offset + 2, offset + 2 + length
    datagrams, findings = [], []
    while cursor < end:
        if len(datagrams) >= MAX_ITEMS:
            raise ParseError("EtherCAT datagram cap exceeded")
        _need(data, cursor, 10, "EtherCAT datagram header")
        command, index = data[cursor], data[cursor + 1]
        address = data[cursor + 2:cursor + 6]
        length_flags = struct.unpack_from("<H", data, cursor + 6)[0]
        payload_length = length_flags & 0x07FF
        irq = struct.unpack_from("<H", data, cursor + 8)[0]
        cursor += 10
        _need(data, cursor, payload_length + 2, "EtherCAT datagram data/WKC")
        payload = data[cursor:cursor + payload_length]
        working_counter = struct.unpack_from("<H", data, cursor + payload_length)[0]
        cursor += payload_length + 2
        name = ETHERCAT_COMMANDS.get(command, f"Unknown 0x{command:02x}")
        row: dict[str, Any] = {"command": command, "command_name": name, "index": index,
                               "circulating": bool(length_flags & 0x4000), "more": bool(length_flags & 0x8000),
                               "irq": irq, "data": payload.hex(), "working_counter": working_counter}
        if command in {1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14}:
            adp, ado = struct.unpack_from("<HH", address)
            row.update(addressing="physical", position_or_station=adp, register=ado)
            if ado in {0x0120, 0x0130} and len(payload) >= 2:
                state_value = struct.unpack_from("<H", payload, 0)[0]
                row["al_state"] = ETHERCAT_STATES.get(state_value & 0xF, "Unknown")
                row["al_error"] = bool(state_value & 0x10)
                if name in {"APWR", "APRW", "FPWR", "FPRW", "BWR", "BRW"} and ado == 0x0120:
                    findings.append(_finding("ethercat-state-write", "high", "EtherCAT datagram writes AL Control state",
                                             datagram=len(datagrams), requested_state=row["al_state"]))
        else:
            row.update(addressing="logical", logical_address=struct.unpack_from("<I", address)[0])
        if working_counter == 0 and command != 0:
            findings.append(_finding("ethercat-zero-wkc", "medium", "EtherCAT datagram has zero working counter",
                                     datagram=len(datagrams), command=name))
        if name in {"APWR", "APRW", "FPWR", "FPRW", "BWR", "BRW", "LWR", "LRW", "ARMW", "FRMW"}:
            findings.append(_finding("ethercat-write", "high", "EtherCAT write-capable datagram is present",
                                     datagram=len(datagrams), command=name))
        if len(payload) >= 6:
            declared = struct.unpack_from("<H", payload, 0)[0]
            mailbox_type = payload[5] & 0x0F
            if declared + 6 == len(payload) and mailbox_type in MAILBOX_TYPES:
                try:
                    row["mailbox"] = parse_ethercat_mailbox(payload)
                    if mailbox_type == 4 and row["mailbox"].get("foe", {}).get("opcode") == 2:
                        findings.append(_finding("ethercat-foe-write", "critical", "FoE write request transfers a file to a slave",
                                                 datagram=len(datagrams), filename=row["mailbox"]["foe"].get("filename")))
                    coe = row["mailbox"].get("coe", {})
                    if mailbox_type == 3 and coe.get("service") == 2 and coe.get("command_specifier") in {0, 1, 3}:
                        findings.append(_finding("ethercat-sdo-download", "high", "CoE SDO request may write an object dictionary entry",
                                                 datagram=len(datagrams), index=coe.get("index"), subindex=coe.get("subindex")))
                except ParseError as exc:
                    row["mailbox_error"] = str(exc)
        datagrams.append(row)
    return {"protocol": "ethercat", "frame_type": frame_type, "length": length,
            "datagrams": datagrams, "findings": _sort_findings(findings)}


# --------------------------------------------------------------------------- PROFINET DCE/RPC and blocks

DCE_PDU_TYPES = {0: "Request", 2: "Response", 3: "Fault", 11: "Bind", 12: "BindAck", 13: "BindNak",
                 14: "AlterContext", 15: "AlterContextResp", 16: "Auth3", 17: "Shutdown", 18: "CoCancel",
                 19: "Orphaned"}
DCE_AUTH_TYPES = {0: "None", 9: "GSS-Negotiate", 10: "NTLM", 14: "Schannel", 16: "Kerberos"}
DCE_AUTH_LEVELS = {1: "None", 2: "Connect", 3: "Call", 4: "Packet", 5: "Integrity", 6: "Privacy"}
PROFINET_BLOCK_TYPES = {
    0x0101: "ARBlockReq", 0x8101: "ARBlockRes", 0x0102: "IOCRBlockReq", 0x8102: "IOCRBlockRes",
    0x0103: "AlarmCRBlockReq", 0x8103: "AlarmCRBlockRes", 0x0104: "ExpectedSubmoduleBlockReq",
    0x8104: "ModuleDiffBlock", 0x0008: "IODWriteReqHeader", 0x8008: "IODWriteResHeader",
    0x0009: "IODReadReqHeader", 0x8009: "IODReadResHeader", 0x0010: "AlarmNotificationHigh",
    0x0011: "AlarmNotificationLow", 0x8001: "PNIOStatus", 0x0500: "DiagnosisBlock",
}
PROFINET_RECORD_INDEXES = {
    0xAFF0: "I&M0", 0xAFF1: "I&M1", 0xAFF2: "I&M2", 0xAFF3: "I&M3", 0xAFF4: "I&M4",
    0xE000: "ExpectedIdentificationData", 0xE001: "RealIdentificationData",
    0xF000: "DiagnosisData", 0xF800: "PDRealData", 0xF841: "PDPortDataReal",
}
PROFINET_ALARM_TYPES = {1: "Diagnosis", 2: "Process", 3: "Pull", 4: "Plug", 5: "Status",
                        6: "Update", 7: "Redundancy", 8: "ControlledBySupervisor", 9: "Released"}


def _uuid_le(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw))


def parse_profinet_block(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
    data = _blob(data)
    _need(data, offset, 6, "PROFINET block header")
    block_type, block_length = struct.unpack_from(">HH", data, offset)
    total = block_length + 4
    if block_length < 2 or total > MAX_FRAME:
        raise ParseError("invalid PROFINET block length")
    _need(data, offset, total, "PROFINET block")
    version_high, version_low = data[offset + 4], data[offset + 5]
    payload = data[offset + 6:offset + total]
    out: dict[str, Any] = {"block_type": block_type, "block_name": PROFINET_BLOCK_TYPES.get(block_type, "Unknown"),
                           "block_length": block_length, "version": f"{version_high}.{version_low}",
                           "payload": payload.hex()}
    if block_type in {0x0008, 0x8008, 0x0009, 0x8009} and len(payload) >= 32:
        sequence = struct.unpack_from(">H", payload, 0)[0]
        ar_uuid = str(uuid.UUID(bytes=payload[2:18]))
        api = struct.unpack_from(">I", payload, 18)[0]
        slot, subslot = struct.unpack_from(">HH", payload, 22)
        index = struct.unpack_from(">H", payload, 28)[0]
        record_length = struct.unpack_from(">I", payload, 30)[0] if len(payload) >= 34 else None
        out["record"] = {"sequence": sequence, "ar_uuid": ar_uuid, "api": api, "slot": slot,
                         "subslot": subslot, "index": index,
                         "index_name": PROFINET_RECORD_INDEXES.get(index), "record_data_length": record_length,
                         "data": payload[34:].hex() if len(payload) > 34 else ""}
        if block_type == 0x0008 and record_length is not None and record_length > len(payload) - 34:
            raise ParseError("PROFINET write record data is shorter than declared")
    elif block_type in {0x0010, 0x0011} and len(payload) >= 20:
        alarm_type = struct.unpack_from(">H", payload, 0)[0]
        api = struct.unpack_from(">I", payload, 2)[0]
        slot, subslot = struct.unpack_from(">HH", payload, 6)
        module_ident, submodule_ident = struct.unpack_from(">II", payload, 10)
        specifier = struct.unpack_from(">H", payload, 18)[0]
        out["alarm"] = {"alarm_type": alarm_type, "alarm_type_name": PROFINET_ALARM_TYPES.get(alarm_type, "Unknown"),
                        "api": api, "slot": slot, "subslot": subslot, "module_ident": module_ident,
                        "submodule_ident": submodule_ident, "specifier": specifier,
                        "sequence": specifier & 0x7FF, "channel_diagnosis": bool(specifier & 0x8000),
                        "manufacturer_diagnosis": bool(specifier & 0x4000), "submodule_diagnosis": bool(specifier & 0x2000),
                        "ar_diagnosis": bool(specifier & 0x1000)}
    elif block_type in {0x0101, 0x8101} and len(payload) >= 16:
        out["ar_uuid"] = str(uuid.UUID(bytes=payload[:16]))
    return out, offset + total


def parse_profinet_blocks(stub: bytes) -> list[dict[str, Any]]:
    stub = _blob(stub)
    # PNIO NDR stubs often carry a 20-byte conformant-array wrapper. Locate the
    # first plausible block header on a 2-byte boundary within that prefix.
    start = None
    for candidate in range(0, min(64, max(0, len(stub) - 5)), 2):
        block_length = struct.unpack_from(">H", stub, candidate + 2)[0]
        version_high = stub[candidate + 4]
        if 2 <= block_length <= len(stub) - candidate - 4 and version_high <= 2:
            start = candidate
            break
    if start is None:
        return []
    blocks, offset = [], start
    while offset < len(stub):
        block, next_offset = parse_profinet_block(stub, offset)
        blocks.append(block)
        if len(blocks) > MAX_ITEMS:
            raise ParseError("PROFINET block cap exceeded")
        offset = next_offset
        while offset < len(stub) and offset % 4 and stub[offset] == 0:
            offset += 1
        if offset == len(stub):
            break
        if len(stub) - offset < 6:
            if any(stub[offset:]):
                raise ParseError("trailing PROFINET NDR bytes")
            break
    return blocks


def parse_dcerpc_pdu(data: bytes) -> dict[str, Any]:
    data = _blob(data)
    _need(data, 0, 16, "DCE/RPC common header")
    version, minor, ptype, flags = data[:4]
    if version != 5:
        raise ParseError("unsupported DCE/RPC version")
    little = bool(data[4] & 0x10)
    endian = "<" if little else ">"
    frag_length, auth_length = struct.unpack_from(endian + "HH", data, 8)
    call_id = struct.unpack_from(endian + "I", data, 12)[0]
    if frag_length != len(data) or frag_length > MAX_FRAME:
        raise ParseError("DCE/RPC fragment length mismatch")
    if auth_length and auth_length + 8 > len(data) - 16:
        raise ParseError("invalid DCE/RPC auth length")
    auth_start = len(data) - auth_length - 8 if auth_length else len(data)
    out: dict[str, Any] = {"version": version, "minor": minor, "packet_type": ptype,
                           "packet_type_name": DCE_PDU_TYPES.get(ptype, "Unknown"), "flags": flags,
                           "first_fragment": bool(flags & 1), "last_fragment": bool(flags & 2),
                           "little_endian": little, "fragment_length": frag_length,
                           "auth_length": auth_length, "call_id": call_id}
    if auth_length:
        auth_type, auth_level, pad_length, reserved, context_id = struct.unpack_from(endian + "BBBBI", data, auth_start)
        if pad_length > auth_start - 16:
            raise ParseError("invalid DCE/RPC auth padding")
        out["auth"] = {"type": auth_type, "type_name": DCE_AUTH_TYPES.get(auth_type, "Unknown"),
                       "level": auth_level, "level_name": DCE_AUTH_LEVELS.get(auth_level, "Unknown"),
                       "pad_length": pad_length, "reserved": reserved, "context_id": context_id,
                       "value_sha256": hashlib.sha256(data[auth_start + 8:]).hexdigest()}
        stub_end = auth_start - pad_length
    else:
        stub_end = len(data)
    offset = 16
    if ptype == 0:
        _need(data, offset, 8, "DCE/RPC request header")
        allocation, context_id, opnum = struct.unpack_from(endian + "IHH", data, offset)
        offset += 8
        out.update(allocation_hint=allocation, context_id=context_id, opnum=opnum)
        if flags & 0x80:
            _need(data, offset, 16, "DCE/RPC object UUID")
            out["object_uuid"] = _uuid_le(data[offset:offset + 16])
            offset += 16
        out["stub"] = data[offset:stub_end].hex()
    elif ptype == 2:
        _need(data, offset, 8, "DCE/RPC response header")
        allocation, context_id, cancel, reserved = struct.unpack_from(endian + "IHBB", data, offset)
        offset += 8
        out.update(allocation_hint=allocation, context_id=context_id, cancel_count=cancel, reserved=reserved,
                   stub=data[offset:stub_end].hex())
    elif ptype == 3:
        _need(data, offset, 16, "DCE/RPC fault header")
        allocation, context_id, cancel, reserved, status, reserved2 = struct.unpack_from(endian + "IHBBII", data, offset)
        offset += 16
        out.update(allocation_hint=allocation, context_id=context_id, cancel_count=cancel,
                   status=status, reserved2=reserved2, stub=data[offset:stub_end].hex())
    elif ptype in {11, 14}:
        _need(data, offset, 12, "DCE/RPC bind header")
        max_xmit, max_recv, assoc_group = struct.unpack_from(endian + "HHI", data, offset)
        context_count = data[offset + 8]
        offset += 12
        if context_count > 255:
            raise ParseError("DCE/RPC context cap exceeded")
        contexts = []
        for _ in range(context_count):
            _need(data, offset, 24, "DCE/RPC presentation context")
            context_id = struct.unpack_from(endian + "H", data, offset)[0]
            transfer_count = data[offset + 2]
            abstract_uuid = _uuid_le(data[offset + 4:offset + 20])
            abstract_version = struct.unpack_from(endian + "I", data, offset + 20)[0]
            offset += 24
            transfers = []
            for _ in range(transfer_count):
                _need(data, offset, 20, "DCE/RPC transfer syntax")
                transfers.append({"uuid": _uuid_le(data[offset:offset + 16]),
                                  "version": struct.unpack_from(endian + "I", data, offset + 16)[0]})
                offset += 20
            contexts.append({"context_id": context_id, "abstract_uuid": abstract_uuid,
                             "abstract_version": abstract_version, "transfer_syntaxes": transfers})
        out.update(max_xmit_fragment=max_xmit, max_receive_fragment=max_recv, association_group=assoc_group,
                   contexts=contexts)
    else:
        out["body"] = data[offset:stub_end].hex()
    if ptype in {0, 2}:
        try:
            out["profinet_blocks"] = parse_profinet_blocks(bytes.fromhex(out["stub"]))
        except ParseError as exc:
            out["profinet_block_error"] = str(exc)
    return out


def reassemble_dcerpc_fragments(fragments: Iterable[bytes]) -> list[dict[str, Any]]:
    pending: dict[tuple[int, int, int], dict[str, Any]] = {}
    completed = []
    for raw in fragments:
        pdu = parse_dcerpc_pdu(raw)
        if pdu["packet_type"] not in {0, 2}:
            completed.append(pdu)
            continue
        key = (pdu["call_id"], pdu["packet_type"], int(pdu.get("context_id", 0)))
        if pdu["first_fragment"]:
            pending[key] = {"header": pdu, "stub": bytearray(), "fragments": 0}
        if key not in pending:
            raise ParseError("DCE/RPC continuation without first fragment")
        state = pending[key]
        state["stub"].extend(bytes.fromhex(pdu.get("stub", "")))
        state["fragments"] += 1
        if len(state["stub"]) > MAX_INPUT:
            raise ParseError("reassembled DCE/RPC stub exceeds cap")
        if pdu["last_fragment"]:
            report = dict(state["header"])
            report["stub"] = bytes(state["stub"]).hex()
            report["fragment_count"] = state["fragments"]
            report["first_fragment"] = report["last_fragment"] = True
            try:
                report["profinet_blocks"] = parse_profinet_blocks(bytes(state["stub"]))
            except ParseError as exc:
                report["profinet_block_error"] = str(exc)
            completed.append(report)
            del pending[key]
    if pending:
        raise ParseError("incomplete DCE/RPC fragment sequence")
    return completed


def analyze_profinet_rpc(data: bytes) -> dict[str, Any]:
    pdu = parse_dcerpc_pdu(data)
    findings = []
    auth = pdu.get("auth")
    if not auth or auth.get("level", 0) < 5:
        findings.append(_finding("profinet-rpc-no-integrity", "medium", "DCE/RPC PDU has no packet-integrity protection",
                                 call_id=pdu["call_id"], auth_level=None if not auth else auth.get("level_name")))
    if pdu.get("packet_type") == 0:
        findings.append(_finding("profinet-rpc-request", "info", "PROFINET DCE/RPC request operation is present",
                                 call_id=pdu["call_id"], opnum=pdu.get("opnum")))
    for block in pdu.get("profinet_blocks", []):
        if block["block_type"] in {0x0008}:
            findings.append(_finding("profinet-record-write", "high", "PROFINET IODWrite request is present",
                                     call_id=pdu["call_id"], index=(block.get("record") or {}).get("index"),
                                     index_name=(block.get("record") or {}).get("index_name")))
        if block.get("alarm"):
            findings.append(_finding("profinet-alarm", "medium", "PROFINET alarm notification is present",
                                     call_id=pdu["call_id"], alarm_type=block["alarm"]["alarm_type_name"],
                                     slot=block["alarm"]["slot"], subslot=block["alarm"]["subslot"]))
    return {"protocol": "profinet-dcerpc", "pdu": pdu, "findings": _sort_findings(findings)}


# --------------------------------------------------------------------------- DNP3 Secure Authentication

DNP3_SA_VARIATIONS = {
    1: "Challenge", 2: "Reply", 3: "AggressiveModeRequest", 4: "SessionKeyStatusRequest",
    5: "SessionKeyStatus", 6: "SessionKeyChange", 7: "Error", 8: "UserCertificate",
    9: "HMACAlgorithm", 10: "UserStatusChange", 11: "UpdateKeyChangeRequest",
    12: "UpdateKeyChangeReply", 13: "UpdateKeyChange", 14: "Signature",
}
DNP3_SA_MACS = {
    1: ("HMAC-SHA1-96", "sha1", 12), 2: ("HMAC-SHA256-128", "sha256", 16),
    3: ("HMAC-SHA256-256", "sha256", 32), 4: ("HMAC-SHA3-256", "sha3_256", 32),
}
DNP3_SA_REASONS = {0: "Critical", 1: "Periodic", 2: "SessionKeyChange", 3: "UserInitiated"}
DNP3_SA_KEY_STATUS = {1: "OK", 2: "NotInitialized", 3: "CommunicationFailure", 4: "AuthenticationFailure"}
DNP3_SA_ERRORS = {1: "AuthenticationFailed", 2: "UnexpectedResponse", 3: "NoResponse",
                  4: "AggressiveModeNotPermitted", 5: "MACNotSupported", 6: "KeyWrapNotSupported",
                  7: "AuthorizationFailed", 8: "UpdateKeyNotPermitted", 9: "UnknownUser"}


def parse_dnp3_sa_object(variation: int, value: bytes) -> dict[str, Any]:
    value = _blob(value)
    name = DNP3_SA_VARIATIONS.get(variation, "Unknown")
    out: dict[str, Any] = {"group": 120, "variation": variation, "variation_name": name, "raw": value.hex()}
    if variation in {1, 2, 3, 5, 6, 7, 11, 12, 13}:
        _need(value, 0, 6, f"DNP3 SA {name}")
        out["sequence"] = struct.unpack_from("<I", value, 0)[0]
        out["user"] = struct.unpack_from("<H", value, 4)[0]
    if variation == 1:
        _need(value, 6, 2, "DNP3 SA Challenge algorithms")
        out["mac_algorithm"] = value[6]
        out["mac_algorithm_name"] = DNP3_SA_MACS.get(value[6], ("Unknown", "", 0))[0]
        out["reason"] = value[7]
        out["reason_name"] = DNP3_SA_REASONS.get(value[7], "Unknown")
        out["challenge_data"] = value[8:].hex()
    elif variation == 2:
        out["mac"] = value[6:].hex()
    elif variation == 3:
        out["mac"] = value[6:].hex()
    elif variation == 4:
        _need(value, 0, 2, "DNP3 SA status request")
        out["user"] = struct.unpack_from("<H", value, 0)[0]
    elif variation == 5:
        _need(value, 6, 3, "DNP3 SA session key status")
        out["key_wrap_algorithm"] = value[6]
        out["key_status"] = value[7]
        out["key_status_name"] = DNP3_SA_KEY_STATUS.get(value[7], "Unknown")
        out["mac_algorithm"] = value[8]
        out["mac_algorithm_name"] = DNP3_SA_MACS.get(value[8], ("Unknown", "", 0))[0]
        out["challenge_data"] = value[9:].hex()
    elif variation in {6, 11, 12, 13}:
        out["wrapped_key_data"] = value[6:].hex()
    elif variation == 7:
        _need(value, 6, 3, "DNP3 SA error")
        out["association_id"] = struct.unpack_from("<H", value, 6)[0]
        out["error_code"] = value[8]
        out["error_name"] = DNP3_SA_ERRORS.get(value[8], "Unknown")
        cursor = 9
        if len(value) >= cursor + 6:
            milliseconds = int.from_bytes(value[cursor:cursor + 6], "little")
            out["time_unix_ms"] = milliseconds
            cursor += 6
        out["error_text"] = value[cursor:].decode("utf-8", "replace")
    elif variation in {8, 14}:
        out["blob"] = value.hex()
    elif variation == 9:
        out["algorithms"] = list(value)
        out["algorithm_names"] = [DNP3_SA_MACS.get(item, ("Unknown", "", 0))[0] for item in value]
    elif variation == 10:
        _need(value, 0, 3, "DNP3 SA user status change")
        out["user"] = struct.unpack_from("<H", value, 0)[0]
        out["status"] = value[2]
        out["data"] = value[3:].hex()
    else:
        out["data"] = value.hex()
    return out


def parse_dnp3_sa_free_format(data: bytes) -> list[dict[str, Any]]:
    data = _blob(data)
    offset = 0
    objects = []
    while offset < len(data):
        _need(data, offset, 4, "DNP3 SA object header/count")
        group, variation, qualifier, count = data[offset:offset + 4]
        offset += 4
        if group != 120 or qualifier not in {0x4B, 0x5B, 0x6B}:
            raise ParseError("expected DNP3 group 120 free-format qualifier")
        if count > MAX_ITEMS:
            raise ParseError("DNP3 SA object count exceeds cap")
        size_width = {0x4B: 1, 0x5B: 2, 0x6B: 4}[qualifier]
        for _ in range(count):
            _need(data, offset, size_width, "DNP3 SA free-format size")
            size = int.from_bytes(data[offset:offset + size_width], "little")
            offset += size_width
            if size > MAX_FRAME:
                raise ParseError("DNP3 SA object size exceeds cap")
            _need(data, offset, size, "DNP3 SA free-format value")
            objects.append(parse_dnp3_sa_object(variation, data[offset:offset + size]))
            offset += size
    return objects


def verify_dnp3_sa_mac(key: bytes, algorithm: int | str, authenticated_data: bytes, mac: bytes) -> dict[str, Any]:
    if not isinstance(key, bytes) or not key:
        raise ValueError("a non-empty supplied key is required")
    if len(key) > MAX_STRING:
        raise ValueError("supplied key exceeds cap")
    authenticated_data = _blob(authenticated_data)
    mac = bytes(mac)
    if isinstance(algorithm, str):
        reverse = {value[0].lower(): key_id for key_id, value in DNP3_SA_MACS.items()}
        try:
            algorithm_id = reverse[algorithm.lower()]
        except KeyError as exc:
            raise ValueError("unsupported DNP3 SA MAC algorithm") from exc
    else:
        algorithm_id = int(algorithm)
    if algorithm_id not in DNP3_SA_MACS:
        raise ValueError("unsupported DNP3 SA MAC algorithm")
    name, digest_name, length = DNP3_SA_MACS[algorithm_id]
    expected = hmac.new(key, authenticated_data, digest_name).digest()[:length]
    return {"algorithm": algorithm_id, "algorithm_name": name, "expected_length": length,
            "provided_length": len(mac), "verified": len(mac) == length and hmac.compare_digest(expected, mac)}


class DNP3SAState:
    """Chronological association state; cryptographic truth requires caller key+MAC input."""

    def __init__(self) -> None:
        self.pending: dict[tuple[int, int], dict[str, Any]] = {}
        self.last_sequence: dict[int, int] = {}
        self.events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []

    def feed(self, obj: dict[str, Any], *, key: bytes | None = None,
             authenticated_data: bytes | None = None) -> dict[str, Any]:
        if len(self.events) >= MAX_ITEMS:
            raise ParseError("DNP3 SA state event cap exceeded")
        if obj.get("group") != 120:
            raise ValueError("state accepts parsed DNP3 group 120 objects only")
        event = dict(obj)
        variation = int(obj.get("variation", -1))
        user = int(obj.get("user", 0))
        sequence = obj.get("sequence")
        if isinstance(sequence, int):
            previous = self.last_sequence.get(user)
            if previous is not None and sequence <= previous and variation not in {2, 3}:
                self.findings.append(_finding("dnp3-sa-sequence-replay", "high", "secure-auth sequence is repeated or regresses",
                                              user=user, previous=previous, sequence=sequence))
            self.last_sequence[user] = max(previous if previous is not None else -1, sequence)
        if variation == 1:
            self.pending[(user, int(sequence))] = event
        elif variation in {2, 3}:
            challenge = self.pending.pop((user, int(sequence)), None) if isinstance(sequence, int) else None
            if challenge is None and variation == 2:
                self.findings.append(_finding("dnp3-sa-reply-without-challenge", "high", "secure-auth reply has no matching challenge",
                                              user=user, sequence=sequence))
            algorithm = challenge.get("mac_algorithm") if challenge else None
            raw_mac = bytes.fromhex(str(obj.get("mac", "")))
            if algorithm in DNP3_SA_MACS and len(raw_mac) != DNP3_SA_MACS[int(algorithm)][2]:
                self.findings.append(_finding("dnp3-sa-mac-length", "high", "secure-auth MAC length does not match the negotiated algorithm",
                                              user=user, sequence=sequence, expected=DNP3_SA_MACS[int(algorithm)][2], actual=len(raw_mac)))
            if key is not None and authenticated_data is not None and algorithm is not None:
                event["mac_verification"] = verify_dnp3_sa_mac(key, int(algorithm), authenticated_data, raw_mac)
                if not event["mac_verification"]["verified"]:
                    self.findings.append(_finding("dnp3-sa-mac-invalid", "critical", "secure-auth MAC verification failed with supplied key/data",
                                                  user=user, sequence=sequence))
            else:
                event["mac_verification"] = {"verified": None, "reason": "key, exact authenticated bytes, and challenge algorithm are required"}
        elif variation == 5 and obj.get("key_status") not in {None, 1}:
            self.findings.append(_finding("dnp3-sa-key-status", "high", "secure-auth session key status is not OK",
                                          user=user, sequence=sequence, status=obj.get("key_status_name")))
        elif variation == 7:
            self.findings.append(_finding("dnp3-sa-error", "high", "secure-auth error object is present",
                                          user=user, sequence=sequence, error=obj.get("error_name")))
        self.events.append(event)
        return event

    def report(self) -> dict[str, Any]:
        return {"events": self.events, "pending_challenges": [dict(value) for _, value in sorted(self.pending.items())],
                "last_sequence": self.last_sequence, "findings": _sort_findings(self.findings)}


# --------------------------------------------------------------------------- historian/HMI supplied artifacts

_SECRET_NAME = re.compile(r"(?i)(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|connectionstring)")
_SCRIPT = re.compile(r"(?i)\b(?:powershell|cmd\.exe|wscript|cscript|/bin/(?:sh|bash)|system\s*\(|shell\s*\(|process\.start|runtime\.exec|eval\s*\()")
_ENDPOINT = re.compile(r"(?i)\b(?:opc\.tcp|https?|mqtt|modbus|s7|dnp3)://[^\s'\"<>]+")


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        number = float(text)
        if number > 10**14:
            number /= 1_000_000
        elif number > 10**11:
            number /= 1000
        try:
            return datetime.fromtimestamp(number, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _column(headers: list[str], patterns: tuple[str, ...]) -> int | None:
    for index, header in enumerate(headers):
        normalized = re.sub(r"[^a-z0-9]", "", header.lower())
        if normalized in patterns or any(pattern in normalized for pattern in patterns):
            return index
    return None


def analyze_historian_csv(data: bytes | str, *, name: str = "") -> dict[str, Any]:
    raw = data.encode() if isinstance(data, str) else _blob(data)
    if len(raw) > MAX_INPUT:
        raise ParseError("CSV exceeds input cap")
    try:
        text = raw.decode("utf-8-sig", "strict")
    except UnicodeDecodeError as exc:
        raise ParseError("historian CSV is not UTF-8") from exc
    sample = text[:64_000]
    delimiter_scores = {delimiter: sample.count(delimiter) for delimiter in (",", ";", "\t", "|")}
    delimiter = max(delimiter_scores, key=delimiter_scores.get)
    if delimiter_scores[delimiter] == 0:
        raise ParseError("unable to identify CSV delimiter")
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    try:
        headers = next(reader)
    except StopIteration as exc:
        raise ParseError("empty CSV") from exc
    if not headers or len(headers) > MAX_COLUMNS:
        raise ParseError("invalid CSV column count")
    headers = [header.strip() for header in headers]
    time_col = _column(headers, ("timestamp", "datetime", "time", "eventtime", "sampletime"))
    tag_col = _column(headers, ("tag", "tagname", "point", "pointname", "itemid", "signal"))
    value_col = _column(headers, ("value", "processvalue", "samplevalue", "pv"))
    quality_col = _column(headers, ("quality", "status", "qualitycode"))
    event_col = _column(headers, ("event", "eventtype", "alarmstate", "action", "message"))
    user_col = _column(headers, ("user", "username", "operator"))
    series: dict[str, list[tuple[datetime | None, Any, str | None]]] = defaultdict(list)
    alarms: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    row_count = 0
    for row_no, row in enumerate(reader, 2):
        if row_count >= MAX_ITEMS:
            raise ParseError("CSV row cap exceeded")
        if len(row) != len(headers):
            findings.append(_finding("historian-row-width", "low", "CSV row width differs from header",
                                     path=name, row=row_no, fields=len(row), expected=len(headers)))
            continue
        row_count += 1
        timestamp = _parse_timestamp(row[time_col]) if time_col is not None else None
        tag = row[tag_col].strip() if tag_col is not None else "<single-series>"
        raw_value = row[value_col].strip() if value_col is not None else None
        try:
            value: Any = float(raw_value) if raw_value not in {None, ""} else raw_value
        except ValueError:
            value = raw_value
        quality = row[quality_col].strip() if quality_col is not None else None
        series[tag].append((timestamp, value, quality))
        if quality and not re.search(r"(?i)^(?:good(?:[_ -].*)?|ok|192|0|0x[cC]0|true)$", quality):
            findings.append(_finding("historian-bad-quality", "medium", "historian sample quality is not good",
                                     path=name, row=row_no, tag=tag, quality=quality))
        event = row[event_col].strip() if event_col is not None else ""
        user = row[user_col].strip() if user_col is not None else None
        if event:
            alarm_key = tag or event
            lower = event.lower()
            state = alarms.setdefault(alarm_key, {"activations": 0, "acks": 0, "clears": 0, "users": set()})
            if re.search(r"alarm|active|raised|trip", lower): state["activations"] += 1
            if re.search(r"ack", lower): state["acks"] += 1
            if re.search(r"clear|return|normal|reset", lower): state["clears"] += 1
            if user: state["users"].add(user)
    summaries = {}
    for tag, points in series.items():
        numeric = [float(value) for _, value, _ in points if isinstance(value, (int, float)) and math.isfinite(float(value))]
        timestamps = [timestamp for timestamp, _, _ in points if timestamp is not None]
        summary: dict[str, Any] = {"samples": len(points), "numeric_samples": len(numeric)}
        if numeric:
            summary.update(min=min(numeric), max=max(numeric), mean=statistics.fmean(numeric),
                           changes=sum(a != b for a, b in zip(numeric, numeric[1:])))
            if len(numeric) >= 5 and len(set(numeric)) == 1:
                findings.append(_finding("historian-flatline", "medium", "tag is flat for all supplied numeric samples",
                                         path=name, tag=tag, samples=len(numeric), value=numeric[0]))
            if len(numeric) >= 7:
                median = statistics.median(numeric)
                mad = statistics.median(abs(value - median) for value in numeric)
                if mad > 0:
                    outliers = [index for index, value in enumerate(numeric) if abs(value - median) > 10 * mad]
                    if outliers:
                        findings.append(_finding("historian-outlier", "low", "tag contains values beyond ten median absolute deviations",
                                                 path=name, tag=tag, count=len(outliers)))
        if timestamps:
            summary.update(first=min(timestamps).isoformat(), last=max(timestamps).isoformat())
            if any(right < left for left, right in zip(timestamps, timestamps[1:])):
                findings.append(_finding("historian-time-regression", "medium", "tag timestamps regress in supplied row order",
                                         path=name, tag=tag))
            intervals = [(right - left).total_seconds() for left, right in zip(timestamps, timestamps[1:]) if right > left]
            if len(intervals) >= 3:
                median_interval = statistics.median(intervals)
                summary["median_interval_seconds"] = median_interval
                if median_interval > 0 and max(intervals) > 10 * median_interval:
                    findings.append(_finding("historian-gap", "medium", "tag has a sampling gap over ten times its median interval",
                                             path=name, tag=tag, maximum_gap_seconds=max(intervals), median_interval_seconds=median_interval))
        summaries[tag] = summary
    alarm_summary = {}
    for key, state in alarms.items():
        alarm_summary[key] = {**state, "users": sorted(state["users"])}
        if state["activations"] > state["acks"]:
            findings.append(_finding("alarm-unacknowledged", "medium", "alarm activations exceed acknowledgements in supplied history",
                                     path=name, alarm=key, activations=state["activations"], acknowledgements=state["acks"]))
    return {"format": "historian-csv", "name": name, "delimiter": delimiter, "headers": headers,
            "columns": {"time": time_col, "tag": tag_col, "value": value_col, "quality": quality_col,
                        "event": event_col, "user": user_col},
            "row_count": row_count, "series": summaries, "alarms": alarm_summary,
            "findings": _sort_findings(findings)}


def _safe_sql_value(value: Any) -> Any:
    if value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        return {"type": "blob", "length": len(value), "sha256": hashlib.sha256(value).hexdigest(),
                "preview": value[:128].hex()}
    text = str(value)
    return text[:4096] + ("…" if len(text) > 4096 else "")


def _qid(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _analyze_sqlite_connection(connection: sqlite3.Connection, *, name: str) -> dict[str, Any]:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
    except sqlite3.DatabaseError:
        pass
    steps = 0

    def progress() -> int:
        nonlocal steps
        steps += 1
        return 1 if steps > 2_000_000 else 0

    connection.set_progress_handler(progress, 1000)
    try:
        schema_rows = connection.execute(
            "SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name LIMIT ?",
            (MAX_TABLES + 1,),
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise ParseError(f"SQLite schema read failed: {exc}") from exc
    if len(schema_rows) > MAX_TABLES:
        raise ParseError("SQLite table cap exceeded")
    tables, findings = [], []
    for schema in schema_rows:
        table_name, table_type, sql = str(schema["name"]), str(schema["type"]), schema["sql"]
        record: dict[str, Any] = {"name": table_name, "type": table_type, "schema": sql}
        if table_type != "table" or table_name.startswith("sqlite_") or re.match(r"(?i)^\s*CREATE\s+VIRTUAL", str(sql or "")):
            record["sample_skipped"] = "only ordinary tables are queried"
            tables.append(record)
            continue
        try:
            columns = connection.execute(f"PRAGMA table_info({_qid(table_name)})").fetchall()
            if len(columns) > MAX_COLUMNS:
                raise ParseError("SQLite column cap exceeded")
            record["columns"] = [{"name": row[1], "type": row[2], "not_null": bool(row[3]),
                                  "default": row[4], "primary_key": bool(row[5])} for row in columns]
            rows = connection.execute(f"SELECT * FROM {_qid(table_name)} LIMIT {MAX_SQL_ROWS + 1}").fetchall()
        except sqlite3.DatabaseError as exc:
            record["read_error"] = str(exc)
            tables.append(record)
            continue
        record["sample_truncated"] = len(rows) > MAX_SQL_ROWS
        rows = rows[:MAX_SQL_ROWS]
        record["sample_row_count"] = len(rows)
        samples = []
        for row_index, row in enumerate(rows):
            sample = {key: _safe_sql_value(row[key]) for key in row.keys()}
            samples.append(sample)
            for key, value in sample.items():
                has_value = value is not None and value != ""
                if _SECRET_NAME.search(str(key)) and has_value:
                    findings.append(_finding("hmi-sqlite-literal-secret", "high", "secret-named SQLite column contains a value",
                                             path=name, table=table_name, row=row_index, column=key, value=value))
                if isinstance(value, str) and _SCRIPT.search(value):
                    findings.append(_finding("hmi-embedded-script", "high", "SQLite value contains a process/script execution primitive",
                                             path=name, table=table_name, row=row_index, column=key, preview=value[:512]))
        record["samples"] = samples
        lower_columns = {str(column["name"]).lower() for column in record["columns"]}
        if lower_columns & {"tag", "tagname", "itemid", "pointname"} and lower_columns & {"value", "samplevalue", "pv"}:
            record["historian_candidate"] = True
        if lower_columns & {"alarm", "alarmstate", "eventtype", "acknowledged", "acktime"}:
            record["alarm_candidate"] = True
        tables.append(record)
    return {"format": "sqlite", "name": name, "tables": tables, "table_count": len(tables),
            "findings": _sort_findings(findings)}


def analyze_historian_sqlite_bytes(data: bytes, *, name: str = "artifact.sqlite") -> dict[str, Any]:
    data = _blob(data)
    if not data.startswith(b"SQLite format 3\0"):
        raise ParseError("SQLite magic is absent")
    connection = sqlite3.connect(":memory:")
    try:
        if not hasattr(connection, "deserialize"):
            raise ParseError("this Python build cannot deserialize SQLite bytes safely")
        try:
            connection.deserialize(data)
        except sqlite3.DatabaseError as exc:
            raise ParseError(f"SQLite deserialize failed: {exc}") from exc
        return _analyze_sqlite_connection(connection, name=name)
    finally:
        connection.close()


def analyze_historian_sqlite_path(path: str | Path) -> dict[str, Any]:
    artifact = Path(path).resolve()
    if artifact.stat().st_size > MAX_INPUT:
        raise ParseError("SQLite artifact exceeds input cap")
    # mode=ro + immutable prevents journal/WAL creation and external mutation.
    uri = "file:" + quote(str(artifact), safe="/") + "?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.DatabaseError as exc:
        raise ParseError(f"SQLite open failed: {exc}") from exc
    try:
        return _analyze_sqlite_connection(connection, name=artifact.name)
    finally:
        connection.close()


def _archive_path(name: str) -> str:
    normalized = name.replace("\\", "/")
    if (not normalized or "\0" in normalized or normalized.startswith("/")
            or any(part == ".." for part in normalized.split("/"))):
        raise ParseError("unsafe HMI archive member path")
    return normalized


def _scan_project_text(text: str, *, path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings = []
    endpoints = sorted(set(_ENDPOINT.findall(text)))[:10_000]
    scripts = []
    for match in _SCRIPT.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        scripts.append({"line": line, "token": match.group(0)})
        findings.append(_finding("hmi-embedded-script", "high", "project text contains a process/script execution primitive",
                                 path=path, line=line, token=match.group(0)))
    for match in re.finditer(r"(?i)\b(password|passwd|secret|token|api[_-]?key|connectionstring)\s*[:=]\s*['\"]?([^\s'\";,<]{4,256})", text):
        findings.append(_finding("hmi-project-literal-secret", "high", "project text contains a literal secret assignment",
                                 path=path, line=text.count("\n", 0, match.start()) + 1,
                                 key=match.group(1), value=match.group(2)))
    tags = sorted(set(re.findall(r"(?i)(?:tag(?:name)?|itemid|pointname)\s*[:=]\s*['\"]([^'\"\r\n<>,;]{1,256})", text)))[:50_000]
    return {"endpoints": endpoints, "tags": tags, "script_tokens": scripts}, findings


def analyze_hmi_project(data: bytes, *, name: str = "project") -> dict[str, Any]:
    data = _blob(data)
    if data.startswith(b"SQLite format 3\0"):
        return analyze_historian_sqlite_bytes(data, name=name)
    if not data.startswith(b"PK\x03\x04"):
        if name.lower().endswith((".csv", ".tsv")):
            return analyze_historian_csv(data, name=name)
        text = data.decode("utf-8", "strict")
        inventory, findings = _scan_project_text(text, path=name)
        return {"format": "hmi-project-text", "name": name, **inventory, "findings": _sort_findings(findings)}
    files, analyses, findings, total = [], [], [], 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ParseError("invalid HMI ZIP project") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_FILES:
            raise ParseError("HMI archive file cap exceeded")
        seen = set()
        for info in infos:
            path = _archive_path(info.filename)
            if path in seen:
                raise ParseError("duplicate HMI archive path")
            seen.add(path)
            if info.is_dir():
                continue
            if info.file_size > MAX_INPUT:
                raise ParseError("HMI archive member exceeds cap")
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL:
                raise ParseError("HMI archive expanded total exceeds cap")
            try:
                body = archive.read(info)
            except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                raise ParseError(f"cannot read HMI archive member {path}: {exc}") from exc
            if len(body) != info.file_size:
                raise ParseError("truncated HMI archive member")
            files.append({"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()})
            lower = path.lower()
            try:
                if body.startswith(b"SQLite format 3\0"):
                    analyses.append({"path": path, "analysis": analyze_historian_sqlite_bytes(body, name=path)})
                    findings.extend(analyses[-1]["analysis"].get("findings", []))
                elif lower.endswith((".csv", ".tsv")):
                    analysis = analyze_historian_csv(body, name=path)
                    analyses.append({"path": path, "analysis": analysis})
                    findings.extend(analysis.get("findings", []))
                elif lower.endswith((".xml", ".json", ".txt", ".ini", ".cfg", ".yaml", ".yml", ".js", ".vbs", ".ps1", ".sql")):
                    text = body.decode("utf-8", "strict")
                    inventory, text_findings = _scan_project_text(text, path=path)
                    analyses.append({"path": path, "analysis": inventory})
                    findings.extend(text_findings)
            except (ParseError, UnicodeDecodeError, sqlite3.DatabaseError) as exc:
                analyses.append({"path": path, "error": str(exc)})
    return {"format": "hmi-project-zip", "name": name, "files": files, "embedded_analyses": analyses,
            "findings": _sort_findings(findings)}


# --------------------------------------------------------------------------- dispatcher/CLI

def analyze_ics_application(data: bytes, *, kind: str, name: str = "") -> dict[str, Any]:
    kind = kind.lower()
    if kind in {"opcua", "opc-ua"}:
        return analyze_opcua_stream(data)
    if kind in {"ethercat", "ecat"}:
        return parse_ethercat_frame(data)
    if kind in {"profinet", "pnio", "dcerpc"}:
        return analyze_profinet_rpc(data)
    if kind in {"dnp3-sa", "dnp3-secure-auth"}:
        objects = parse_dnp3_sa_free_format(data)
        state = DNP3SAState()
        for obj in objects:
            state.feed(obj)
        return {"protocol": "dnp3-secure-auth", "objects": objects, **state.report()}
    if kind in {"hmi", "project"}:
        return analyze_hmi_project(data, name=name)
    if kind in {"csv", "historian-csv"}:
        return analyze_historian_csv(data, name=name)
    if kind in {"sqlite", "historian-sqlite"}:
        return analyze_historian_sqlite_bytes(data, name=name)
    raise ValueError(f"unsupported ICS application kind: {kind}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline OPC UA/EtherCAT/PROFINET/DNP3-SA/HMI artifact analysis")
    parser.add_argument("kind", choices=("opcua", "ethercat", "profinet", "dnp3-sa", "hmi", "csv", "sqlite"))
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    report = analyze_ics_application(args.artifact.read_bytes(), kind=args.kind, name=args.artifact.name)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
