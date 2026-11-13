#!/usr/bin/env python3
"""Passive OpenADR 2.0b/3.0.x and SAE EV-grid signaling analysis.

The input to this module is an already-supplied XML/JSON artifact.  It never opens
a connection, resolves an XML resource, executes document content, or constructs a
message for transmission.  OpenADR 2 XML signatures are inventoried structurally;
their presence is never reported as cryptographic verification.
"""

from __future__ import annotations

import argparse
import copy
import functools
import json
import math
from datetime import datetime
from pathlib import Path
import re
import sys
from typing import Any, Callable
from urllib.parse import urlsplit


MAX_INPUT_BYTES = 8 << 20
MAX_XML_NODES = 50_000
MAX_XML_DEPTH = 64
MAX_XML_ATTRIBUTES = 200_000
MAX_TEXT_BYTES = 8 << 20
MAX_TEXT_ITEM_BYTES = 1 << 20
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_JSON_MEMBERS = 4_096
MAX_JSON_STRING_BYTES = 1 << 20
MAX_INTERVALS = 20_000

OADR_NS = "http://openadr.org/oadr-2.0b/2012/07"
EI_NS = "http://docs.oasis-open.org/ns/energyinterop/201110"
EI_PAYLOAD_NS = "http://docs.oasis-open.org/ns/energyinterop/201110/payloads"
EMIX_NS = "http://docs.oasis-open.org/ns/emix/2011/06"
EMIX_POWER_NS = "http://docs.oasis-open.org/ns/emix/2011/06/power"
EMIX_SCALE_NS = "http://docs.oasis-open.org/ns/emix/2011/06/siscale"
XCAL_NS = "urn:ietf:params:xml:ns:icalendar-2.0"
STREAM_NS = "urn:ietf:params:xml:ns:icalendar-2.0:stream"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
REPLAY_NS = "http://openadr.org/oadr-2.0b/2012/07/xmldsig-properties"
ESPI_NS = "http://naesb.org/espi"
ATOM_NS = "http://www.w3.org/2005/Atom"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XML_NS = "http://www.w3.org/XML/1998/namespace"
XINCLUDE_NS = "http://www.w3.org/2001/XInclude"
GML_NS = "http://www.opengis.net/gml/3.2"
GMLSF_NS = "http://www.opengis.net/gmlsf/2.0"
DS11_NS = "http://www.w3.org/2009/xmldsig11#"
ISO4217_NS = "urn:un:unece:uncefact:codelist:standard:5:ISO42173A:2010-04-07"

_OPENADR2_DATETIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?$"
)
_OPENADR2_DURATION = re.compile(
    r"^[+-]?P(?=\d|T\d)(?:\d+Y)?(?:\d+M)?(?:\d+[DW])?"
    r"(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$"
)

_KNOWN_ELEMENT_NAMESPACES = frozenset({
    OADR_NS, EI_NS, EI_PAYLOAD_NS, EMIX_NS, EMIX_POWER_NS, EMIX_SCALE_NS,
    XCAL_NS, STREAM_NS, DS_NS, REPLAY_NS, ESPI_NS, ATOM_NS,
    GML_NS, GMLSF_NS, DS11_NS, ISO4217_NS,
})

OPENADR2_OPERATIONS = frozenset({
    "oadrCancelOpt", "oadrCanceledOpt", "oadrCancelPartyRegistration",
    "oadrCanceledPartyRegistration", "oadrCancelReport", "oadrCanceledReport",
    "oadrCreateOpt", "oadrCreatedOpt", "oadrCreatePartyRegistration",
    "oadrCreatedPartyRegistration", "oadrCreateReport", "oadrCreatedReport",
    "oadrDistributeEvent", "oadrCreatedEvent", "oadrPoll", "oadrQueryRegistration",
    "oadrRegisterReport", "oadrRegisteredReport", "oadrRequestEvent",
    "oadrRequestReregistration", "oadrResponse", "oadrUpdateReport",
    "oadrUpdatedReport",
})

# Instance-element namespaces from the published OpenADR 2.0b XSD family.
# Extraction is namespace-pinned so an allowed but unrelated namespace cannot
# win a local-name lookup (for example ds:eventID inside an EI descriptor).
_FIELD_NAMESPACES: dict[str, tuple[str, ...]] = {
    "value": (EI_NS, ESPI_NS),
    "rID": (EI_NS,), "confidence": (EI_NS,), "accuracy": (EI_NS,),
    "oadrDataQuality": (OADR_NS,),
    "uid": (XCAL_NS, EI_NS), "dtstart": (XCAL_NS,), "duration": (XCAL_NS,),
    "startafter": (XCAL_NS,),
    "x-eiNotification": (EI_NS,), "x-eiRampUp": (EI_NS,), "x-eiRecovery": (EI_NS,),
    "eiTarget": (EI_NS,), "eiActivePeriod": (EI_NS,), "eiEvent": (EI_NS,),
    "eventDescriptor": (EI_NS,), "eiEventSignal": (EI_NS,), "interval": (EI_NS,),
    "eventID": (EI_NS,), "modificationNumber": (EI_NS,), "priority": (EI_NS,),
    "marketContext": (EMIX_NS,), "createdDateTime": (EI_NS,), "eventStatus": (EI_NS,),
    "testEvent": (EI_NS,), "vtnComment": (EI_NS,), "signalID": (EI_NS,),
    "signalName": (EI_NS,), "signalType": (EI_NS,), "currentValue": (EI_NS,),
    "signalPayload": (EI_NS,), "oadrResponseRequired": (OADR_NS,),
    "venID": (EI_NS,), "resourceID": (EI_NS,), "groupID": (EI_NS,),
    "partyID": (EI_NS,), "groupName": (EI_NS,), "serviceArea": (EMIX_NS,),
    "serviceLocation": (EMIX_POWER_NS,),
    "itemBase": (EMIX_NS,), "itemDescription": (OADR_NS, EMIX_POWER_NS),
    "itemUnits": (OADR_NS, EMIX_POWER_NS), "siScaleCode": (EMIX_SCALE_NS,),
    "reportType": (EI_NS,), "readingType": (EI_NS,), "eiReportID": (EI_NS,),
    "reportRequestID": (EI_NS,), "reportSpecifierID": (EI_NS,), "reportName": (EI_NS,),
    "granularity": (XCAL_NS,), "reportBackDuration": (EI_NS,), "reportInterval": (EI_NS,),
    "oadrReportDescription": (OADR_NS,), "oadrReportPayload": (OADR_NS,),
    "requestID": (EI_PAYLOAD_NS,), "vtnID": (EI_NS,),
}


class SecEvchargeOpenADRError(ValueError):
    """The supplied OpenADR/SAE artifact is malformed, unsafe, or unsupported."""


def _closed(function: Callable[..., Any]) -> Callable[..., Any]:
    """Make every public API fail through the one declared exception type."""

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except SecEvchargeOpenADRError:
            raise
        except Exception as exc:
            raise SecEvchargeOpenADRError(
                f"analysis failed: {type(exc).__name__}: {str(exc)[:240]}"
            ) from None

    return wrapper


def _bounded_bytes(value: bytes | bytearray | memoryview | str, label: str) -> bytes:
    if isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeError as exc:
            raise SecEvchargeOpenADRError(f"{label} is not valid UTF-8") from exc
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raise SecEvchargeOpenADRError(f"{label} must be bytes-like or text")
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise SecEvchargeOpenADRError(
            f"{label} must contain 1..{MAX_INPUT_BYTES} bytes"
        )
    return raw


def _qname(node: Any) -> tuple[str | None, str]:
    from lxml import etree

    if not isinstance(getattr(node, "tag", None), str):
        return None, ""
    qname = etree.QName(node)
    return qname.namespace, qname.localname


def _children(node: Any) -> list[Any]:
    return [child for child in node if isinstance(getattr(child, "tag", None), str)]


def _descendants(node: Any, local: str, namespace: str | None = None) -> list[Any]:
    rows = []
    allowed = (namespace,) if namespace is not None else _FIELD_NAMESPACES.get(local)
    for child in node.iter():
        child_ns, child_local = _qname(child)
        if child_local == local and (allowed is None or child_ns in allowed):
            rows.append(child)
    return rows


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _element_value(node: Any) -> str | None:
    for child in node.iter():
        value = _clean_text(child.text)
        if value is not None:
            return value
    return None


def _first_value(node: Any, local: str) -> str | None:
    matches = _descendants(node, local)
    return _element_value(matches[0]) if matches else None


def _field_values(node: Any, local: str, *, limit: int = 1_024) -> list[str]:
    values = []
    for child in _descendants(node, local):
        value = _element_value(child)
        if value is not None and value not in values:
            values.append(value)
            if len(values) > limit:
                raise SecEvchargeOpenADRError(f"too many {local} values")
    return values


def _typed_scalar(text: str | None) -> Any:
    if text is None:
        return None
    if text in {"true", "false"}:
        return text == "true"
    if re.fullmatch(r"[+-]?[0-9]+", text) and len(text) <= 20:
        value = int(text, 10)
        if -(1 << 63) <= value <= (1 << 63) - 1:
            return value
        raise SecEvchargeOpenADRError("numeric XML value exceeds signed 64-bit bounds")
    if re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", text):
        value = float(text)
        if math.isfinite(value):
            return value
        raise SecEvchargeOpenADRError("non-finite XML number is forbidden")
    if text.casefold() in {"nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"}:
        raise SecEvchargeOpenADRError("non-finite XML number is forbidden")
    return text


def _parse_xml(value: bytes | bytearray | memoryview | str) -> Any:
    try:
        from lxml import etree
    except ImportError as exc:
        raise SecEvchargeOpenADRError("lxml is required for safe OpenADR XML parsing") from exc

    raw = _bounded_bytes(value, "OpenADR XML")
    lower = raw.lower()
    if b"<!doctype" in lower or b"<!entity" in lower:
        raise SecEvchargeOpenADRError("DTD and entity declarations are forbidden")
    if re.search(br"<\?(?!xml(?:\s|\?))", raw, re.IGNORECASE):
        raise SecEvchargeOpenADRError("XML processing instructions are forbidden")

    class _DenyResolver(etree.Resolver):
        def resolve(self, url: str, pubid: str, context: Any) -> Any:
            raise SecEvchargeOpenADRError("external XML resources are forbidden")

    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
        recover=False,
        remove_pis=False,
    )
    parser.resolvers.add(_DenyResolver())
    try:
        root = etree.fromstring(raw, parser=parser)
    except (etree.XMLSyntaxError, ValueError, TypeError) as exc:
        raise SecEvchargeOpenADRError(f"malformed OpenADR XML: {str(exc)[:240]}") from None
    tree = root.getroottree()
    if tree.docinfo.doctype:
        raise SecEvchargeOpenADRError("DOCTYPE is forbidden")
    if tree.xpath("//processing-instruction()"):
        raise SecEvchargeOpenADRError("XML processing instructions are forbidden")

    node_count = attribute_count = text_bytes = 0
    for node in root.iter():
        node_count += 1
        if node_count > MAX_XML_NODES:
            raise SecEvchargeOpenADRError("XML node limit exceeded")
        depth = sum(1 for _ in node.iterancestors()) + 1
        if depth > MAX_XML_DEPTH:
            raise SecEvchargeOpenADRError("XML depth limit exceeded")
        namespace, local = _qname(node)
        if not local:
            continue
        if namespace == XINCLUDE_NS:
            raise SecEvchargeOpenADRError("XInclude is forbidden")
        if namespace not in _KNOWN_ELEMENT_NAMESPACES:
            raise SecEvchargeOpenADRError(
                f"unsupported element namespace {namespace!r} on {local}"
            )
        attribute_count += len(node.attrib)
        if len(node.attrib) > 64 or attribute_count > MAX_XML_ATTRIBUTES:
            raise SecEvchargeOpenADRError("XML attribute limit exceeded")
        for key, attr_value in node.attrib.items():
            if len(str(key).encode("utf-8")) > 512 or len(attr_value.encode("utf-8")) > 16_384:
                raise SecEvchargeOpenADRError("XML attribute exceeds its size limit")
        for text in (node.text, node.tail):
            if text is None:
                continue
            size = len(text.encode("utf-8"))
            if size > MAX_TEXT_ITEM_BYTES:
                raise SecEvchargeOpenADRError("XML text item exceeds its size limit")
            text_bytes += size
            if text_bytes > MAX_TEXT_BYTES:
                raise SecEvchargeOpenADRError("XML text limit exceeded")
    return root


def _xml_ids(root: Any) -> dict[str, Any]:
    identifiers: dict[str, Any] = {}
    for node in root.iter():
        for raw_name, value in node.attrib.items():
            try:
                from lxml import etree

                local = etree.QName(raw_name).localname
            except Exception:
                local = str(raw_name)
            if local.lower() != "id":
                continue
            if not value or len(value.encode("utf-8")) > 512:
                raise SecEvchargeOpenADRError("XML ID must be bounded nonempty text")
            if value in identifiers:
                raise SecEvchargeOpenADRError(f"duplicate XML ID {value!r}")
            identifiers[value] = node
    return identifiers


def _signature_inventory(root: Any, signed_object: Any, identifiers: dict[str, Any]) -> dict[str, Any]:
    signatures = _descendants(root, "Signature", DS_NS)
    signed_id = None
    for attr_name, value in signed_object.attrib.items():
        try:
            from lxml import etree

            if etree.QName(attr_name).localname.lower() == "id":
                signed_id = value
                break
        except Exception:
            continue
    indicators: list[dict[str, Any]] = []
    profile_indicators: list[dict[str, Any]] = []
    if len(signatures) > 1:
        indicators.append({"code": "multiple-signatures", "count": len(signatures)})
    records = []
    direct_signatures = set(_children(root))
    for signature_index, signature in enumerate(signatures):
        if signature not in direct_signatures:
            indicators.append({"code": "signature-not-direct-child", "index": signature_index})
        methods = {}
        for local, key in (
            ("CanonicalizationMethod", "canonicalization"),
            ("SignatureMethod", "signature"),
            ("DigestMethod", "digest"),
        ):
            values = []
            for method in _descendants(signature, local, DS_NS):
                algorithm = method.get("Algorithm")
                if algorithm:
                    if len(algorithm) > 512:
                        raise SecEvchargeOpenADRError("XML signature algorithm URI is oversized")
                    values.append(algorithm)
            methods[key] = values
        references = []
        for reference_index, reference in enumerate(_descendants(signature, "Reference", DS_NS)):
            uri = reference.get("URI")
            if uri is None or len(uri) > 1_024:
                raise SecEvchargeOpenADRError("XML signature reference URI is missing or oversized")
            resolved = False
            target = "document" if uri == "" else None
            if uri.startswith("#") and len(uri) > 1:
                target_id = uri[1:]
                resolved = target_id in identifiers
                target = target_id
                if not resolved:
                    indicators.append({
                        "code": "unresolved-signature-reference", "signature": signature_index,
                        "reference": reference_index, "uri": uri,
                    })
                elif signed_id is not None and target_id != signed_id:
                    indicators.append({
                        "code": "reference-does-not-target-signed-object",
                        "signature": signature_index, "reference": reference_index,
                        "target": target_id, "expected": signed_id,
                    })
            elif uri == "":
                resolved = True
            else:
                indicators.append({
                    "code": "external-signature-reference", "signature": signature_index,
                    "reference": reference_index, "uri": uri,
                })
            transforms = [
                node.get("Algorithm")
                for node in _descendants(reference, "Transform", DS_NS)
                if node.get("Algorithm")
            ]
            references.append({
                "uri": uri, "resolved_within_document": resolved, "target": target,
                "transforms": transforms,
            })
        replay_nodes = _descendants(signature, "ReplayProtect", REPLAY_NS)
        replay_record: dict[str, Any] = {
            "present": bool(replay_nodes), "count": len(replay_nodes),
            "timestamp": None, "nonce_present": False,
        }
        if len(replay_nodes) != 1:
            profile_indicators.append({
                "code": "missing-replay-protect" if not replay_nodes else "multiple-replay-protect",
                "signature": signature_index, "count": len(replay_nodes),
            })
        else:
            replay = replay_nodes[0]
            parent = replay.getparent()
            if parent is None or _qname(parent) != (DS_NS, "SignatureProperty"):
                profile_indicators.append({
                    "code": "replay-protect-not-in-signature-property",
                    "signature": signature_index,
                })
            timestamp_nodes = _descendants(replay, "timestamp", REPLAY_NS)
            nonce_nodes = _descendants(replay, "nonce", REPLAY_NS)
            timestamp = _element_value(timestamp_nodes[0]) if len(timestamp_nodes) == 1 else None
            nonce = _element_value(nonce_nodes[0]) if len(nonce_nodes) == 1 else None
            replay_record.update(timestamp=timestamp, nonce_present=nonce is not None)
            if timestamp is None:
                profile_indicators.append({
                    "code": "missing-replay-protect-timestamp", "signature": signature_index,
                })
            else:
                try:
                    _datetime_value(timestamp, "ReplayProtect.timestamp")
                except SecEvchargeOpenADRError:
                    profile_indicators.append({
                        "code": "invalid-replay-protect-timestamp", "signature": signature_index,
                    })
            if nonce is None or len(nonce.encode("utf-8")) > 1_024:
                profile_indicators.append({
                    "code": "missing-or-oversized-replay-protect-nonce",
                    "signature": signature_index,
                })
        records.append({
            "methods": methods, "references": references,
            "replay_protect": replay_record,
        })
    if signatures and signed_id is None:
        indicators.append({"code": "signed-object-has-no-id"})
    return {
        "present": bool(signatures),
        "count": len(signatures),
        "signed_object_id": signed_id,
        "signatures": records,
        "wrapping_indicators": indicators,
        "profile_indicators": profile_indicators,
        "cryptographically_verified": False,
        "verification_limitation": (
            "Structural inventory only; no key, certificate, digest, canonicalization, "
            "signature validation, ReplayProtect freshness, or nonce-reuse check was performed."
        ),
    }


def _payload_record(node: Any) -> dict[str, Any]:
    values = []
    for value_node in _descendants(node, "value"):
        text = _clean_text(value_node.text)
        if text is None:
            continue
        parent = value_node.getparent()
        _, value_type = _qname(parent) if parent is not None else (None, "value")
        typed_value = _typed_scalar(text)
        if "float" in value_type.casefold() and type(typed_value) not in (int, float):
            raise SecEvchargeOpenADRError("payloadFloat value is not a finite number")
        values.append({"type": value_type, "value": typed_value, "text": text})
    confidence = _typed_scalar(_first_value(node, "confidence"))
    accuracy = _typed_scalar(_first_value(node, "accuracy"))
    if confidence is not None and (type(confidence) is not int or not 0 <= confidence <= 100):
        raise SecEvchargeOpenADRError("report confidence must be an integer from 0 through 100")
    if accuracy is not None and type(accuracy) not in (int, float):
        raise SecEvchargeOpenADRError("report accuracy must be a finite number")
    record: dict[str, Any] = {
        "r_id": _first_value(node, "rID"),
        "confidence": confidence,
        "accuracy": accuracy,
        "data_quality": _first_value(node, "oadrDataQuality"),
        "values": values,
    }
    if len(values) == 1:
        record["value"] = values[0]["value"]
        record["value_type"] = values[0]["type"]
    return record


def _interval_record(node: Any, payload_local: str) -> dict[str, Any]:
    payloads = [_payload_record(payload) for payload in _descendants(node, payload_local)]
    return {
        "uid": _first_value(node, "uid"),
        "start": _first_value(node, "dtstart"),
        "duration": _first_value(node, "duration"),
        "payloads": payloads,
    }


def _openadr2_datetime(value: str, field: str) -> None:
    """Validate the XML Schema date-time lexical space used by OpenADR 2."""

    if len(value) > 80 or not _OPENADR2_DATETIME.fullmatch(value):
        raise SecEvchargeOpenADRError(f"{field} is not an OpenADR date-time")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise SecEvchargeOpenADRError(f"{field} is not a real calendar date-time") from exc


def _openadr2_duration(value: str, field: str) -> None:
    if len(value) > 80 or not _OPENADR2_DURATION.fullmatch(value):
        raise SecEvchargeOpenADRError(f"{field} is not an OpenADR duration")


def _validate_openadr2_temporal_fields(root: Any) -> None:
    limit = MAX_INTERVALS + 1_024
    for local in ("createdDateTime", "dtstart"):
        for value in _field_values(root, local, limit=limit):
            _openadr2_datetime(value, local)
    for local in (
        "duration", "x-eiNotification", "x-eiRampUp", "x-eiRecovery",
        "startafter", "granularity", "reportBackDuration",
    ):
        for value in _field_values(root, local, limit=limit):
            _openadr2_duration(value, local)


def _target_record(event: Any) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}
    target_nodes = _descendants(event, "eiTarget")
    if not target_nodes:
        return targets
    target = target_nodes[0]
    for local in (
        "venID", "resourceID", "groupID", "partyID", "groupName",
        "serviceArea", "serviceLocation",
    ):
        values = _field_values(target, local)
        if values:
            targets[local] = values
    return targets


def _active_period(event: Any) -> dict[str, Any] | None:
    nodes = _descendants(event, "eiActivePeriod")
    if not nodes:
        return None
    node = nodes[0]
    record = {
        "start": _first_value(node, "dtstart"),
        "duration": _first_value(node, "duration"),
        "notification": _first_value(node, "x-eiNotification"),
        "ramp_up": _first_value(node, "x-eiRampUp"),
        "recovery": _first_value(node, "x-eiRecovery"),
        "tolerance": {
            "start_after": _first_value(node, "startafter"),
        },
    }
    return record


def _event_record(wrapper: Any) -> dict[str, Any]:
    event_nodes = _descendants(wrapper, "eiEvent")
    if len(event_nodes) != 1:
        raise SecEvchargeOpenADRError("each oadrEvent must contain exactly one eiEvent")
    event = event_nodes[0]
    descriptor_nodes = _descendants(event, "eventDescriptor")
    if len(descriptor_nodes) != 1:
        raise SecEvchargeOpenADRError("each eiEvent must contain one eventDescriptor")
    descriptor_node = descriptor_nodes[0]
    descriptor = {
        "event_id": _first_value(descriptor_node, "eventID"),
        "modification_number": _typed_scalar(_first_value(descriptor_node, "modificationNumber")),
        "priority": _typed_scalar(_first_value(descriptor_node, "priority")),
        "market_context": _first_value(descriptor_node, "marketContext"),
        "created_date_time": _first_value(descriptor_node, "createdDateTime"),
        "event_status": _first_value(descriptor_node, "eventStatus"),
        "test_event": _first_value(descriptor_node, "testEvent"),
        "comment": _first_value(descriptor_node, "vtnComment"),
    }
    if descriptor["event_id"] is None or descriptor["modification_number"] is None:
        raise SecEvchargeOpenADRError("eventDescriptor requires eventID and modificationNumber")
    if (type(descriptor["modification_number"]) is not int
            or not 0 <= descriptor["modification_number"] <= 0xFFFFFFFF):
        raise SecEvchargeOpenADRError("modificationNumber must be an unsigned 32-bit integer")
    if (descriptor["priority"] is not None
            and (type(descriptor["priority"]) is not int
                 or not 0 <= descriptor["priority"] <= 0xFFFFFFFF)):
        raise SecEvchargeOpenADRError("event priority must be an unsigned 32-bit integer")
    if descriptor["event_status"] not in {"none", "far", "near", "active", "completed", "cancelled"}:
        raise SecEvchargeOpenADRError("eventStatus is not a defined OpenADR 2.0b value")
    signals = []
    interval_count = 0
    for signal in _descendants(event, "eiEventSignal"):
        interval_nodes = _descendants(signal, "interval")
        interval_count += len(interval_nodes)
        if interval_count > MAX_INTERVALS:
            raise SecEvchargeOpenADRError("OpenADR event interval cap exceeded")
        signals.append({
            "signal_id": _first_value(signal, "signalID"),
            "signal_name": _first_value(signal, "signalName"),
            "signal_type": _first_value(signal, "signalType"),
            "current_value": _typed_scalar(_first_value(signal, "currentValue")),
            "intervals": [_interval_record(interval, "signalPayload") for interval in interval_nodes],
        })
    response_required = _first_value(wrapper, "oadrResponseRequired")
    if response_required not in ("always", "never"):
        raise SecEvchargeOpenADRError("invalid oadrResponseRequired value")
    return {
        "descriptor": descriptor,
        "active_period": _active_period(event),
        "signals": signals,
        "targets": _target_record(event),
        "response_required": response_required,
    }


def _measurement(description: Any) -> dict[str, Any] | None:
    item_bases = _descendants(description, "itemBase")
    if item_bases:
        children = _children(item_bases[0])
        measurement_node = children[0] if children else item_bases[0]
    else:
        # EMIX measurement types are normally substitution-group elements (for
        # example power:powerReal), so the literal abstract itemBase need not
        # appear on the wire.  Select only a node carrying the item facets.
        candidates = [
            node for node in description.iter()
            if _first_value(node, "itemUnits") is not None
            and _first_value(node, "siScaleCode") is not None
        ]
        if not candidates:
            return None
        measurement_node = candidates[-1]
    _, kind = _qname(measurement_node)
    return {
        "kind": kind,
        "description": _first_value(measurement_node, "itemDescription"),
        "units": _first_value(measurement_node, "itemUnits"),
        "scale": _first_value(measurement_node, "siScaleCode"),
    }


def _report_description(node: Any) -> dict[str, Any]:
    return {
        "r_id": _first_value(node, "rID"),
        "report_type": _first_value(node, "reportType"),
        "reading_type": _first_value(node, "readingType"),
        "market_context": _first_value(node, "marketContext"),
        "measurement": _measurement(node),
    }


def _report_record(node: Any) -> dict[str, Any]:
    interval_nodes = _descendants(node, "interval")
    if len(interval_nodes) > MAX_INTERVALS:
        raise SecEvchargeOpenADRError("OpenADR report interval cap exceeded")
    return {
        "report_id": _first_value(node, "eiReportID"),
        "report_request_id": _first_value(node, "reportRequestID"),
        "report_specifier_id": _first_value(node, "reportSpecifierID"),
        "report_name": _first_value(node, "reportName"),
        "created_date_time": _first_value(node, "createdDateTime"),
        "descriptions": [
            _report_description(description)
            for description in _descendants(node, "oadrReportDescription")
        ],
        "intervals": [
            _interval_record(interval, "oadrReportPayload") for interval in interval_nodes
        ],
    }


def _report_request(node: Any) -> dict[str, Any]:
    return {
        "report_request_id": _first_value(node, "reportRequestID"),
        "report_specifier_id": _first_value(node, "reportSpecifierID"),
        "granularity": _first_value(node, "granularity"),
        "report_back_duration": _first_value(node, "reportBackDuration"),
        "report_interval": _first_value(node, "reportInterval"),
    }


def _parse_openadr2(value: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    root = _parse_xml(value)
    if _qname(root) != (OADR_NS, "oadrPayload"):
        raise SecEvchargeOpenADRError("expected OpenADR 2.0b oadrPayload root")
    direct = _children(root)
    signed_objects = [node for node in direct if _qname(node) == (OADR_NS, "oadrSignedObject")]
    if len(signed_objects) != 1:
        raise SecEvchargeOpenADRError("oadrPayload must contain exactly one oadrSignedObject")
    for node in direct:
        if node is signed_objects[0] or _qname(node) == (DS_NS, "Signature"):
            continue
        raise SecEvchargeOpenADRError("oadrPayload contains an unsupported direct child")
    direct_signatures = [node for node in direct if _qname(node) == (DS_NS, "Signature")]
    for node in _descendants(root, "Signature", DS_NS):
        if node not in direct_signatures:
            raise SecEvchargeOpenADRError("XMLDSig Signature must be a direct oadrPayload child")
    tree = root.getroottree()
    signature_paths = {
        tree.getpath(node) for signature in direct_signatures for node in signature.iter()
    }
    for node in root.iter():
        namespace, _local = _qname(node)
        if namespace in {DS_NS, DS11_NS} and tree.getpath(node) not in signature_paths:
            raise SecEvchargeOpenADRError(
                "XMLDSig elements are allowed only inside the direct Signature subtree"
            )
    signed_object = signed_objects[0]
    operations = _children(signed_object)
    if len(operations) != 1:
        raise SecEvchargeOpenADRError("oadrSignedObject must contain exactly one operation")
    operation = operations[0]
    operation_ns, operation_name = _qname(operation)
    if operation_ns != OADR_NS or operation_name not in OPENADR2_OPERATIONS:
        raise SecEvchargeOpenADRError("unknown or incorrectly namespaced OpenADR 2.0b operation")
    schema_version = (
        operation.get(f"{{{EI_NS}}}schemaVersion")
        or operation.get(f"{{{OADR_NS}}}schemaVersion")
        or operation.get("schemaVersion")
    )
    if schema_version is not None and schema_version != "2.0b":
        raise SecEvchargeOpenADRError("operation schemaVersion is not OpenADR 2.0b")
    _validate_openadr2_temporal_fields(operation)
    identifiers = _xml_ids(root)
    events = [_event_record(event) for event in _descendants(operation, "oadrEvent", OADR_NS)]
    reports = [_report_record(report) for report in _descendants(operation, "oadrReport", OADR_NS)]
    report_requests = [
        _report_request(request)
        for request in _descendants(operation, "oadrReportRequest", OADR_NS)
    ]
    if sum(len(report["intervals"]) for report in reports) > MAX_INTERVALS:
        raise SecEvchargeOpenADRError("OpenADR report interval cap exceeded")
    return {
        "format": "openadr-2.0b",
        "xsd_validated": False,
        "operation": operation_name,
        "request_id": _first_value(operation, "requestID"),
        "vtn_id": _first_value(operation, "vtnID"),
        "ven_id": _first_value(operation, "venID"),
        "schema_version": schema_version,
        "events": events,
        "reports": reports,
        "report_requests": report_requests,
        "signature": _signature_inventory(root, signed_object, identifiers),
        "xml_id_count": len(identifiers),
        "limitations": [
            "Published namespaces and key profile structures are checked, but this is not full multi-XSD validation.",
            "XMLDSig is structurally inventoried but is not cryptographically verified.",
            "Transport, endpoint identity, and VEN/VTN authorization are outside this supplied-payload analysis.",
        ],
    }


@_closed
def parse_openadr2(value: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    """Parse one exact, bounded OpenADR 2.0b XML payload."""

    return _parse_openadr2(value)


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SecEvchargeOpenADRError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _bad_constant(value: str) -> Any:
    raise SecEvchargeOpenADRError(f"non-finite JSON number {value!r} is forbidden")


def _validate_json_tree(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise SecEvchargeOpenADRError("JSON node limit exceeded")
        if depth > MAX_JSON_DEPTH:
            raise SecEvchargeOpenADRError("JSON depth limit exceeded")
        if node is None or isinstance(node, bool):
            continue
        if isinstance(node, int):
            if not -(1 << 63) <= node <= (1 << 63) - 1:
                raise SecEvchargeOpenADRError("JSON integer exceeds signed 64-bit bounds")
            continue
        if isinstance(node, float):
            if not math.isfinite(node):
                raise SecEvchargeOpenADRError("non-finite JSON number is forbidden")
            continue
        if isinstance(node, str):
            try:
                size = len(node.encode("utf-8"))
            except UnicodeError as exc:
                raise SecEvchargeOpenADRError("JSON contains an invalid Unicode scalar") from exc
            if size > MAX_JSON_STRING_BYTES:
                raise SecEvchargeOpenADRError("JSON string limit exceeded")
            continue
        if isinstance(node, list):
            if len(node) > MAX_JSON_MEMBERS:
                raise SecEvchargeOpenADRError("JSON array member limit exceeded")
            stack.extend((item, depth + 1) for item in node)
            continue
        if isinstance(node, dict):
            if len(node) > MAX_JSON_MEMBERS:
                raise SecEvchargeOpenADRError("JSON object member limit exceeded")
            for key, item in node.items():
                if type(key) is not str or not key or len(key.encode("utf-8")) > 512:
                    raise SecEvchargeOpenADRError("JSON object key is invalid or oversized")
                stack.append((item, depth + 1))
            continue
        raise SecEvchargeOpenADRError(f"unsupported JSON value type {type(node).__name__}")


def _strict_json(value: bytes | bytearray | memoryview | str) -> Any:
    raw = _bounded_bytes(value, "OpenADR JSON")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SecEvchargeOpenADRError("JSON byte-order marks are forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecEvchargeOpenADRError("OpenADR JSON is not valid UTF-8") from exc
    decoder = json.JSONDecoder(
        object_pairs_hook=_pairs_without_duplicates,
        parse_constant=_bad_constant,
    )
    start = len(text) - len(text.lstrip())
    try:
        parsed, end = decoder.raw_decode(text, start)
    except SecEvchargeOpenADRError:
        raise
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise SecEvchargeOpenADRError(f"malformed OpenADR JSON: {str(exc)[:240]}") from None
    if text[end:].strip():
        raise SecEvchargeOpenADRError("trailing data after the JSON value")
    _validate_json_tree(parsed)
    return parsed


_O3_KINDS = frozenset({
    "program", "event", "report", "subscription", "ven", "resource",
    "interval", "valuesMap",
})
_O3_REQUIRED = {
    "program": ("programName",),
    "event": ("programID", "intervals"),
    "report": ("programID", "eventID", "clientName", "resources"),
    "subscription": ("clientName", "programID", "objectOperations"),
    "ven": ("venName",),
    "resource": ("resourceName",),
    "interval": ("id", "payloads"),
    "valuesMap": ("type", "values"),
}
_O3_OBJECT_TYPES = {
    "program": "PROGRAM", "event": "EVENT", "report": "REPORT",
    "subscription": "SUBSCRIPTION", "ven": "VEN", "resource": "RESOURCE",
}
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_DURATION = re.compile(
    r"^-?P(?=\d|T\d)(?:\d+Y)?(?:\d+M)?(?:\d+[DW])?"
    r"(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$"
)
_OBJECT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_OBJECT_TYPES = frozenset({"PROGRAM", "EVENT", "REPORT", "SUBSCRIPTION", "VEN", "RESOURCE"})
_OBJECT_OPERATIONS_BY_VERSION = {
    "3.0.0": frozenset({"GET", "POST", "PUT", "DELETE"}),
    "3.0.1": frozenset({"READ", "CREATE", "UPDATE", "DELETE"}),
}


def _o3_version(version: Any) -> str:
    if type(version) is not str or version not in {"3.0.0", "3.0.1"}:
        raise SecEvchargeOpenADRError("OpenADR version must be exactly '3.0.0' or '3.0.1'")
    return version


def _nonempty_string(value: Any, field: str, *, maximum: int = 1_024) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise SecEvchargeOpenADRError(f"{field} must be bounded nonempty text")
    return value


def _datetime_value(value: Any, field: str) -> None:
    if type(value) is not str or not _RFC3339.fullmatch(value):
        raise SecEvchargeOpenADRError(f"{field} must be an RFC 3339 timestamp with an offset")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise SecEvchargeOpenADRError(f"{field} is not a real calendar timestamp") from exc
    if parsed.tzinfo is None:
        raise SecEvchargeOpenADRError(f"{field} lacks a time-zone offset")


def _duration_value(value: Any, field: str) -> None:
    if type(value) is not str or len(value) > 80 or not _DURATION.fullmatch(value):
        raise SecEvchargeOpenADRError(f"{field} must be a bounded ISO 8601 duration")


def _validate_time_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_time_fields(item, f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        item_path = f"{path}.{key}"
        if key.endswith("DateTime") and item is not None:
            _datetime_value(item, item_path)
        if key == "timeZoneOffset" and item is not None:
            _duration_value(item, item_path)
        if key == "intervalPeriod" and item is not None:
            if not isinstance(item, dict):
                raise SecEvchargeOpenADRError(f"{item_path} must be an object")
            if "start" not in item:
                raise SecEvchargeOpenADRError(f"{item_path} is missing required start")
            _datetime_value(item["start"], item_path + ".start")
            for duration_key in ("duration", "randomizeStart"):
                if duration_key in item and item[duration_key] is not None:
                    _duration_value(item[duration_key], item_path + "." + duration_key)
        _validate_time_fields(item, item_path)


def _validate_values_map(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise SecEvchargeOpenADRError(f"{path} must be an object")
    for required in _O3_REQUIRED["valuesMap"]:
        if required not in value:
            raise SecEvchargeOpenADRError(f"{path} is missing {required}")
    _nonempty_string(value["type"], path + ".type", maximum=128)
    values = value["values"]
    if not isinstance(values, list) or len(values) > MAX_JSON_MEMBERS:
        raise SecEvchargeOpenADRError(f"{path}.values must be a bounded array")
    for index, item in enumerate(values):
        item_path = f"{path}.values[{index}]"
        if item is None:
            raise SecEvchargeOpenADRError(f"{item_path} is not an OpenADR valuesMap scalar or point")
        if type(item) in (bool, int, float, str):
            continue
        if not isinstance(item, dict) or "x" not in item or "y" not in item:
            raise SecEvchargeOpenADRError(f"{item_path} must be a scalar or x/y point")
        if (type(item["x"]) not in (int, float) or type(item["y"]) not in (int, float)
                or not math.isfinite(item["x"]) or not math.isfinite(item["y"])):
            raise SecEvchargeOpenADRError(f"{item_path} point coordinates must be finite numbers")


def _validate_interval(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise SecEvchargeOpenADRError(f"{path} must be an interval object")
    for required in _O3_REQUIRED["interval"]:
        if required not in value:
            raise SecEvchargeOpenADRError(f"{path} is missing {required}")
    if type(value["id"]) is not int or not -(1 << 31) <= value["id"] <= (1 << 31) - 1:
        raise SecEvchargeOpenADRError(f"{path}.id must be a signed 32-bit integer")
    payloads = value["payloads"]
    if not isinstance(payloads, list) or len(payloads) > MAX_JSON_MEMBERS:
        raise SecEvchargeOpenADRError(f"{path}.payloads must be a bounded array")
    for index, payload in enumerate(payloads):
        _validate_values_map(payload, f"{path}.payloads[{index}]")


def _normalize_o3_kind(kind: Any) -> str:
    if type(kind) is not str:
        raise SecEvchargeOpenADRError("OpenADR 3 resource kind must be text")
    aliases = {"values_map": "valuesMap", "valuesmap": "valuesMap"}
    normalized = aliases.get(kind, kind)
    if normalized not in _O3_KINDS:
        raise SecEvchargeOpenADRError(
            "resource kind must be program, event, report, subscription, ven, resource, interval, or valuesMap"
        )
    return normalized


def _object_id(value: Any, field: str) -> str:
    if type(value) is not str or not _OBJECT_ID.fullmatch(value):
        raise SecEvchargeOpenADRError(
            f"{field} must be a 1..128 character URL-safe OpenADR object ID"
        )
    return value


def _absolute_uri(value: Any, field: str) -> str:
    text = _nonempty_string(value, field, maximum=MAX_JSON_STRING_BYTES)
    if any(char.isspace() for char in text) or not urlsplit(text).scheme:
        raise SecEvchargeOpenADRError(f"{field} must be an absolute URI")
    return text


def _validate_o3_object(value: Any, version: str, kind: str) -> dict[str, Any]:
    _o3_version(version)
    kind = _normalize_o3_kind(kind)
    if not isinstance(value, dict):
        raise SecEvchargeOpenADRError(f"OpenADR 3 {kind} must be a JSON object")
    for required in _O3_REQUIRED[kind]:
        if required not in value:
            raise SecEvchargeOpenADRError(f"OpenADR 3 {kind} is missing required field {required}")
    expected_type = _O3_OBJECT_TYPES.get(kind)
    if "objectType" in value:
        if expected_type is None or value["objectType"] != expected_type:
            raise SecEvchargeOpenADRError(
                f"OpenADR 3 {kind} objectType must be {expected_type!r}"
            )
    for name in ("id", "programID", "eventID", "venID"):
        if name in value and value[name] is not None:
            _object_id(value[name], f"{kind}.{name}")
    if "clientName" in value and value["clientName"] is not None:
        _nonempty_string(value["clientName"], f"{kind}.clientName", maximum=128)
    if "priority" in value:
        if type(value["priority"]) is not int or value["priority"] < 0:
            raise SecEvchargeOpenADRError(
                f"{kind}.priority must be a nonnegative integer"
            )
    if kind == "program":
        _nonempty_string(value["programName"], "program.programName", maximum=128)
    elif kind == "event":
        _object_id(value["programID"], "event.programID")
        intervals = value["intervals"]
        if not isinstance(intervals, list) or len(intervals) > MAX_INTERVALS:
            raise SecEvchargeOpenADRError("event.intervals must be a bounded array")
        for index, interval in enumerate(intervals):
            _validate_interval(interval, f"event.intervals[{index}]")
    elif kind == "report":
        for name in ("programID", "eventID"):
            _object_id(value[name], f"report.{name}")
        _nonempty_string(value["clientName"], "report.clientName", maximum=128)
        resources = value["resources"]
        if not isinstance(resources, list) or len(resources) > MAX_JSON_MEMBERS:
            raise SecEvchargeOpenADRError("report.resources must be a bounded array")
        for index, resource in enumerate(resources):
            path = f"report.resources[{index}]"
            if not isinstance(resource, dict):
                raise SecEvchargeOpenADRError(f"{path} must be a report-resource object")
            if "resourceName" not in resource or "intervals" not in resource:
                raise SecEvchargeOpenADRError(f"{path} requires resourceName and intervals")
            _nonempty_string(resource["resourceName"], path + ".resourceName", maximum=128)
            intervals = resource["intervals"]
            if not isinstance(intervals, list) or len(intervals) > MAX_INTERVALS:
                raise SecEvchargeOpenADRError(f"{path}.intervals must be a bounded array")
            for interval_index, interval in enumerate(intervals):
                _validate_interval(interval, f"{path}.intervals[{interval_index}]")
    elif kind == "subscription":
        _nonempty_string(value["clientName"], "subscription.clientName", maximum=128)
        _object_id(value["programID"], "subscription.programID")
        operations = value["objectOperations"]
        if not isinstance(operations, list) or len(operations) > MAX_JSON_MEMBERS:
            raise SecEvchargeOpenADRError("subscription.objectOperations must be a bounded array")
        for index, operation in enumerate(operations):
            path = f"subscription.objectOperations[{index}]"
            if not isinstance(operation, dict):
                raise SecEvchargeOpenADRError(f"{path} must be an object")
            missing = {"objects", "operations", "callbackUrl"} - operation.keys()
            if missing:
                raise SecEvchargeOpenADRError(f"{path} lacks {', '.join(sorted(missing))}")
            objects, verbs = operation["objects"], operation["operations"]
            if (not isinstance(objects, list) or len(objects) > MAX_JSON_MEMBERS
                    or any(type(item) is not str or item not in _OBJECT_TYPES for item in objects)):
                raise SecEvchargeOpenADRError(f"{path}.objects has invalid object types")
            allowed_operations = _OBJECT_OPERATIONS_BY_VERSION[version]
            if (not isinstance(verbs, list) or len(verbs) > MAX_JSON_MEMBERS
                    or any(type(item) is not str or item not in allowed_operations for item in verbs)):
                raise SecEvchargeOpenADRError(
                    f"{path}.operations has invalid operations for OpenADR {version}"
                )
            _absolute_uri(operation["callbackUrl"], path + ".callbackUrl")
    elif kind == "ven":
        _nonempty_string(value["venName"], "ven.venName", maximum=128)
    elif kind == "resource":
        _nonempty_string(value["resourceName"], "resource.resourceName", maximum=128)
    elif kind == "interval":
        _validate_interval(value, "interval")
    else:
        _validate_values_map(value, "valuesMap")
    _validate_time_fields(value)
    return {
        "format": "openadr-3",
        "version": version,
        "resource_kind": kind,
        "object_type": value.get("objectType"),
        "id": value.get("id"),
        "object": value,
        "valid": True,
        "validation_scope": (
            "Pinned structural/semantic OpenADR 3.0.x subset; transport and authorization are not evaluated."
        ),
    }


@_closed
def parse_openadr3(
    value: bytes | bytearray | memoryview | str,
    *,
    version: str,
    resource_kind: str,
) -> dict[str, Any]:
    """Parse and validate one caller-typed OpenADR 3.0.0/3.0.1 JSON resource."""

    parsed = _strict_json(value)
    return _validate_o3_object(parsed, _o3_version(version), resource_kind)


_BUNDLE_KEYS = {
    "programs": "program", "events": "event", "reports": "report",
    "subscriptions": "subscription", "vens": "ven", "resources": "resource",
}


def _bundle_objects(value: Any) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    grouped: dict[str, list[dict[str, Any]]] = {kind: [] for kind in _BUNDLE_KEYS.values()}
    supplied: set[str] = set()
    if isinstance(value, list):
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                raise SecEvchargeOpenADRError(f"bundle object {index} must be an object")
            object_type = item.get("objectType")
            matches = [kind for kind, expected in _O3_OBJECT_TYPES.items() if expected == object_type]
            if len(matches) != 1:
                raise SecEvchargeOpenADRError(
                    "list-form bundles require an exact objectType on every object"
                )
            grouped[matches[0]].append(item)
            supplied.add(matches[0])
        return grouped, supplied
    if not isinstance(value, dict) or not value:
        raise SecEvchargeOpenADRError("bundle must be a nonempty object or array")
    unknown = set(value) - set(_BUNDLE_KEYS)
    if unknown:
        raise SecEvchargeOpenADRError(f"unknown bundle collections: {', '.join(sorted(unknown))}")
    for plural, objects in value.items():
        kind = _BUNDLE_KEYS[plural]
        supplied.add(kind)
        if not isinstance(objects, list) or len(objects) > MAX_JSON_MEMBERS:
            raise SecEvchargeOpenADRError(f"bundle collection {plural} must be a bounded array")
        if any(not isinstance(item, dict) for item in objects):
            raise SecEvchargeOpenADRError(f"bundle collection {plural} contains a non-object")
        grouped[kind].extend(objects)
    return grouped, supplied


@_closed
def analyze_openadr3_bundle(
    value: bytes | bytearray | memoryview | str | dict[str, Any] | list[Any],
    *,
    version: str,
) -> dict[str, Any]:
    """Validate supplied OpenADR 3 objects and check only supplied reference domains."""

    version = _o3_version(version)
    if isinstance(value, (bytes, bytearray, memoryview, str)):
        parsed = _strict_json(value)
    else:
        parsed = value
        _validate_json_tree(parsed)
    grouped, supplied = _bundle_objects(parsed)
    for kind, objects in grouped.items():
        for item in objects:
            _validate_o3_object(item, version, kind)

    identifiers: dict[str, dict[str, dict[str, Any]]] = {}
    issues: list[dict[str, Any]] = []
    for kind, objects in grouped.items():
        by_id: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(objects):
            identifier = item.get("id")
            if identifier is None:
                continue
            if identifier in by_id:
                issues.append({
                    "code": "duplicate-id", "kind": kind, "id": identifier,
                    "index": index,
                })
            else:
                by_id[identifier] = item
        identifiers[kind] = by_id

    def check(source_kind: str, source_index: int, field: str, target_kind: str, ref: Any) -> None:
        if target_kind not in supplied:
            return
        if ref not in identifiers[target_kind]:
            issues.append({
                "code": "unresolved-reference", "source_kind": source_kind,
                "source_index": source_index, "field": field,
                "target_kind": target_kind, "value": ref,
            })

    for index, event in enumerate(grouped["event"]):
        check("event", index, "programID", "program", event["programID"])
    for index, report in enumerate(grouped["report"]):
        check("report", index, "programID", "program", report["programID"])
        check("report", index, "eventID", "event", report["eventID"])
    for index, subscription in enumerate(grouped["subscription"]):
        check("subscription", index, "programID", "program", subscription["programID"])
    for index, resource in enumerate(grouped["resource"]):
        if "venID" in resource:
            check("resource", index, "venID", "ven", resource["venID"])

    return {
        "format": "openadr-3-bundle",
        "version": version,
        "counts": {kind: len(objects) for kind, objects in grouped.items()},
        "supplied_collections": sorted(supplied),
        "issues": issues,
        "valid": not issues,
        "reference_scope": (
            "A reference is checked only when its target collection was supplied; no live VTN lookup is performed."
        ),
    }


_SAE_STANDARDS = {
    "J2836/1": {
        "role": "smart-charging use cases",
        "maps_to": ["J2847/1", "IEEE 2030.5 / SEP2"],
    },
    "J2836/3": {
        "role": "bidirectional/DER use cases",
        "maps_to": ["J2847/3", "IEEE 2030.5 DER Function Set", "Flow Reservation"],
    },
    "J2847/1": {
        "revision": "202505",
        "role": "J2836/1 smart-charging application mapping",
        "application_protocol": "Smart Energy Profile 2.0 / IEEE 2030.5",
    },
    "J2847/2": {
        "revision": "202309",
        "role": "PEV to off-board DC charger, forward energy flow",
        "layers": ["J1772 control pilot", "J2931/4 HomePlug Green PHY", "J2931/7 security"],
    },
    "J2847/3": {
        "revision": "202311",
        "role": "bidirectional EV/DER application mapping",
        "application_protocol": "IEEE 2030.5 DER Function Set and Flow Reservation",
    },
    "J2847/5": {
        "revision": "202509",
        "role": "customer-facing V2L/V2V bidirectional onboard-charger modes",
    },
    "J2931/1": {
        "revision": "202309",
        "role": "overall PEV/EVSE/utility/ESI/AMI/HAN communication architecture",
    },
    "J2931/4": {
        "revision": "202305",
        "role": "HomePlug Green PHY physical/data-link selections over the J1772 pilot",
    },
    "J2931/7": {
        "revision": "202608",
        "role": "PEV communication security requirements",
    },
    "J2953": {
        "role": "PEV/EVSE interoperability testing family",
    },
    "IEEE 2030.5": {
        "role": "SEP2 application layer selected by J2847/1 and J2847/3",
    },
    "HomePlug Green PHY": {
        "role": "PLC physical/data-link technology selected by J2931/4",
    },
}

_SAE_USE_CASES = {
    "smart-charging": ["J2836/1", "J2847/1", "IEEE 2030.5"],
    "bidirectional-der": ["J2836/3", "J2847/3", "IEEE 2030.5"],
    "dc-forward-charging": ["J2847/2", "J2931/4", "J2931/7", "J1772"],
    "communications-architecture": ["J2931/1"],
    "plc-physical-link": ["J2931/4", "HomePlug Green PHY"],
    "security": ["J2931/7"],
    "interoperability": ["J2953"],
    "vehicle-to-load-or-vehicle": ["J2847/5"],
}


@_closed
def sae_catalog(standard: str | None = None) -> dict[str, Any]:
    """Return the SAE EV-grid layer catalog; it deliberately has no packet decoder."""

    if standard is None:
        standards = copy.deepcopy(_SAE_STANDARDS)
    else:
        if type(standard) is not str or not standard or len(standard) > 128:
            raise SecEvchargeOpenADRError("SAE standard selector must be bounded text")
        aliases = {key.casefold(): key for key in _SAE_STANDARDS}
        selected = aliases.get(standard.casefold())
        if selected is None:
            raise SecEvchargeOpenADRError(f"unknown SAE/IEEE selector {standard!r}")
        standards = {selected: copy.deepcopy(_SAE_STANDARDS[selected])}
    return {
        "format": "sae-ev-grid-catalog-v1",
        "standards": standards,
        "use_case_mappings": copy.deepcopy(_SAE_USE_CASES),
        "generic_wire_format": None,
        "limitation": (
            "J2847/J2931 is a standards family, not one generic frame. "
            "Use a dedicated IEEE 2030.5 or HomePlug/SLAC parser for supplied traffic."
        ),
    }


@_closed
def map_sae_use_case(use_case: str) -> dict[str, Any]:
    """Map one caller-selected EV-grid use-case label to its standards stack."""

    if type(use_case) is not str or use_case not in _SAE_USE_CASES:
        raise SecEvchargeOpenADRError(
            f"use_case must be one of {', '.join(sorted(_SAE_USE_CASES))}"
        )
    return {
        "use_case": use_case,
        "standards": list(_SAE_USE_CASES[use_case]),
        "passive_only": True,
        "wire_decoder": None,
    }


def _read_file(path: str) -> bytes:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise SecEvchargeOpenADRError(f"cannot read input file: {exc}") from None
    if not data or len(data) > MAX_INPUT_BYTES:
        raise SecEvchargeOpenADRError("input file is empty or exceeds the size cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    openadr2_parser = subparsers.add_parser("openadr2", help="parse OpenADR 2.0b XML")
    openadr2_parser.add_argument("file")

    openadr3_parser = subparsers.add_parser("openadr3", help="parse one OpenADR 3 JSON resource")
    openadr3_parser.add_argument("file")
    openadr3_parser.add_argument("--version", choices=("3.0.0", "3.0.1"), required=True)
    openadr3_parser.add_argument(
        "--type", dest="resource_kind",
        choices=tuple(sorted(_O3_KINDS)), required=True,
    )

    bundle_parser = subparsers.add_parser("bundle", help="check supplied OpenADR 3 references")
    bundle_parser.add_argument("file")
    bundle_parser.add_argument("--version", choices=("3.0.0", "3.0.1"), required=True)

    sae_parser = subparsers.add_parser("sae", help="show SAE EV-grid standards mapping")
    sae_parser.add_argument("standard", nargs="?")

    try:
        args = parser.parse_args(argv)
        if args.command == "openadr2":
            result = parse_openadr2(_read_file(args.file))
        elif args.command == "openadr3":
            result = parse_openadr3(
                _read_file(args.file), version=args.version,
                resource_kind=args.resource_kind,
            )
        elif args.command == "bundle":
            result = analyze_openadr3_bundle(_read_file(args.file), version=args.version)
        else:
            result = sae_catalog(args.standard)
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except SecEvchargeOpenADRError as exc:
        print(f"sec_evcharge_openadr: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"sec_evcharge_openadr: analysis failed: {type(exc).__name__}: {str(exc)[:240]}",
            file=sys.stderr,
        )
        return 2


__all__ = [
    "SecEvchargeOpenADRError", "OPENADR2_OPERATIONS", "parse_openadr2",
    "parse_openadr3", "analyze_openadr3_bundle", "sae_catalog",
    "map_sae_use_case", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
